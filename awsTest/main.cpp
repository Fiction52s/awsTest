#include <aws/core/Aws.h>
#include <aws/core/utils/logging/ConsoleLogSystem.h>
#include <aws/core/utils/memory/stl/AWSStreamFwd.h>

#include <aws/s3/S3Client.h>
#include <aws/s3/model/Bucket.h>

#include <aws/cognito-identity/CognitoIdentityClient.h>
#include <aws/cognito-identity/CognitoIdentity_EXPORTS.h>
#include <aws/cognito-identity/CognitoIdentityEndpoint.h>
#include <aws/cognito-identity/CognitoIdentityErrorMarshaller.h>
#include <aws/cognito-identity/CognitoIdentityErrors.h>
#include <aws/cognito-identity/CognitoIdentityRequest.h>
#include <aws/cognito-identity/model/CognitoIdentityProvider.h>
#include <aws/cognito-identity/model/GetCredentialsForIdentityRequest.h>
#include <aws/cognito-identity/model/GetIdRequest.h>

#include <aws/cognito-idp/CognitoIdentityProviderClient.h>
#include <aws/cognito-idp/model/InitiateAuthRequest.h>
#include <aws/cognito-idp/model/ChangePasswordRequest.h>
#include <aws/cognito-idp/model/RespondToAuthChallengeRequest.h>

#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>

#include <aws/s3/model/DeleteObjectRequest.h>

#include <aws/identity-management/auth/PersistentCognitoIdentityProvider.h>
#include <aws/identity-management/auth/CognitoCachingCredentialsProvider.h>

#include <fstream>
#include <iostream>

#include <Windows.h>
#include <winhttp.h>

#undef GetObject
#undef GetMessage
#undef DELETE

#include "ClientID.h"
#include "nlohmann\json.hpp"

using namespace std;
using namespace Aws;
using namespace Aws::CognitoIdentity::Model;

using std::cout;

using json = nlohmann::json;

struct CustomMapEntry
{
	int id;
	string name;
	string creatorName;

	//json jsonObj;

	CustomMapEntry()
	{

	}

	void Set(const json &j)
	{
		id = j["id"];
		name = j["name"];
		creatorName = j["creatorName"];
	}

	std::string GetMapFileName()
	{
		return string(name + ".brknk");
	}

	std::string CreateKey()
	{
		return string(creatorName + "/" + GetMapFileName());
	}

	//CustomMapEntry(const std::string &p_name, const std::string &p_creatorName)
	//{
	//	//id = -1;
	//	name = p_name;
	//	creatorName = p_creatorName;
	//}

	//void AddToJSON()// bool withID = false )
	//{
	//	json j;
	//	/*if (withID)
	//	{
	//	j["id"] = id;
	//	}*/
	//	j["id"] = id;
	//	j["name"] = name;
	//	j["creatorName"] = creatorName;
	//}
};


namespace HttpVerb
{
	static LPCWSTR GET = L"GET";
	static LPCWSTR POST = L"POST";
	static LPCWSTR PUT = L"PUT";
	static LPCWSTR DELETE = L"DELETE";
}

struct ServerConnection
{
	HINTERNET myConnection;
	HINTERNET mySession;
	HINTERNET myRequest;
	string sessionHeaderName;
	LPCWSTR ContentType_JSON;
	

	ServerConnection()
	{
		sessionHeaderName = "Session-Token:";
		ContentType_JSON = L"Content-Type:application/json";
		myConnection = NULL;
		mySession = NULL;
		myRequest = NULL;
	}

	HINTERNET OpenRequest(LPCWSTR verb, LPCWSTR path)
	{
		HINTERNET req = NULL;
		if (myConnection != NULL)
			req = WinHttpOpenRequest(myConnection, verb, path,
				NULL, WINHTTP_NO_REFERER,
				WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

		return req;
	}

	DWORD GetRequestStatusCode()
	{
		DWORD statusCode = 0;
		DWORD statusCodeSize = sizeof(DWORD);

		//get the status code
		if (!WinHttpQueryHeaders(myRequest,
			WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			WINHTTP_HEADER_NAME_BY_INDEX,
			&statusCode, &statusCodeSize,
			WINHTTP_NO_HEADER_INDEX))
		{
			DWORD error = HRESULT_FROM_WIN32(::GetLastError());
			cout << "Error getting error code: " << error << endl;
			return error;
		}
		else
		{
			//cout << "status code: " << statusCode << endl;
			return statusCode;
		}
	}

	string GetRequestData()
	{
		DWORD dwSize = 0;
		LPSTR pszOutBuffer = NULL;
		DWORD dwDownloaded = 0;
		string response;

		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(myRequest, &dwSize))
				printf("Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());

			if (!dwSize)
			{
				break;
			}

			// Allocate space for the buffer.
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				printf("Out of memory\n");
				dwSize = 0;
			}
			else
			{
				// Read the data.
				ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(myRequest, (LPVOID)pszOutBuffer,
					dwSize, &dwDownloaded))
				{
					printf("Error %u in WinHttpReadData.\n", GetLastError());
					return response;
				}
				else
				{
					//printf("%s", pszOutBuffer);
					response = response + string(pszOutBuffer);
				}

				// Free the memory allocated to the buffer.
				delete[] pszOutBuffer;
			}
		} while (dwSize > 0);


		return response;
	}

	string GetRequestHeaders()
	{
		DWORD dwSize = 0;
		LPCWSTR lpOutBuffer = NULL;
		BOOL bResults;
		string result;

		WinHttpQueryHeaders(myRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
			WINHTTP_HEADER_NAME_BY_INDEX, NULL,
			&dwSize, WINHTTP_NO_HEADER_INDEX);

		// Allocate memory for the buffer.
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			lpOutBuffer = new WCHAR[dwSize / sizeof(WCHAR)];

			// Now, use WinHttpQueryHeaders to retrieve the header.
			bResults = WinHttpQueryHeaders(myRequest,
				WINHTTP_QUERY_RAW_HEADERS_CRLF,
				WINHTTP_HEADER_NAME_BY_INDEX,
				(LPVOID)lpOutBuffer, &dwSize,
				WINHTTP_NO_HEADER_INDEX);

			if (bResults)
			{
				wstring wideBufferStr(lpOutBuffer);
				result = string(wideBufferStr.begin(), wideBufferStr.end());
			}

			//printf("Header contents: \n%S", lpOutBuffer);

			delete[] lpOutBuffer;
		}

		return result;
	}

	void CleanupServerConnection()
	{
		if (myConnection != NULL) WinHttpCloseHandle(myConnection);
		if (mySession != NULL) WinHttpCloseHandle(mySession);

		myConnection = NULL;
		mySession = NULL;
	}

	bool ConnectToServer()
	{
		DWORD dwSize = 0;
		DWORD dwDownloaded = 0;
		BOOL  bResults = FALSE;

		assert(mySession == NULL);
		assert(myConnection == NULL);

		mySession = WinHttpOpen(L"WinHTTP Example/1.0",
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);

		if (mySession != NULL)
		{
			myConnection = WinHttpConnect(mySession, L"localhost",
				8080, 0);
		}

		if (myConnection == NULL)
		{
			CleanupServerConnection();
			mySession = NULL;
			return false;
		}
		else
		{
			return true;
		}
	}

	bool AddHeaderContentTypeJSON()
	{
		return WinHttpAddRequestHeaders(myRequest, ContentType_JSON, -1, WINHTTP_ADDREQ_FLAG_ADD);
	}

	bool AddHeaderSessionToken( const std::string &accessToken )
	{
		string sessionHeader = sessionHeaderName + accessToken;
		wstring wideSessionHeader = wstring(sessionHeader.begin(), sessionHeader.end());
		LPCWSTR wsh = wideSessionHeader.c_str();

		return WinHttpAddRequestHeaders(myRequest, wsh, -1, WINHTTP_ADDREQ_FLAG_ADD);
	}

	bool SendRequestWithMessage(const std::string &message)
	{
		const LPSTR messageBuf = (LPTSTR)message.c_str();
		return WinHttpSendRequest(myRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, messageBuf, strlen(messageBuf), strlen(messageBuf), 0);
	}

	bool SendRequest()
	{
		return WinHttpSendRequest(myRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);
	}

	bool RequestMapUpload(const string &mapName, const std::string &accessToken)
	{
		myRequest = OpenRequest(HttpVerb::POST, L"/MapServer/rest/maps");

		bool okay = false;
		if (myRequest != NULL)
		{
			AddHeaderContentTypeJSON();
			AddHeaderSessionToken(accessToken);

			json j;
			j["name"] = mapName;
			string message = j.dump();

			/*string message = "{"
			"\"name\":\"" + mapName + "\""
			"}";*/

			if (SendRequestWithMessage(message))
			{
				if (WinHttpReceiveResponse(myRequest, NULL))
				{
					int statusCode = GetRequestStatusCode();
					//string headers = GetRequestHeaders();
					//string data = GetRequestData();

					//cout << "status code: " << statusCode << endl;
					//cout << "headers: " << endl;
					//cout << headers << endl;

					//cout << "return data:" << endl;
					//cout << data << endl;

					if (statusCode == 200)
					{
						cout << "you are allowed to upload the map." << endl;
						//string fullPath = username + "/" + mapName;
						//Aws::String awsFullPath(fullPath.c_str());
						okay = true;
					}
					else if (statusCode == 304) //not modified for now
					{
						cout << "you aren't allowed to upload the map. It either already exists or the name is invalid." << endl;
					}
					//process POST result here to see if its okay to upload
				}
			}
			else
			{
				cout << "sending create map request failed" << endl;
			}

			WinHttpCloseHandle(myRequest);
			myRequest = NULL;
		}
		else
		{
			cout << "failed to create request" << endl;
		}

		return okay;
	}

	bool RequestMapDeletion(int id, const std::string & accessToken )
	{
		wstring path = L"/MapServer/rest/maps/" + to_wstring(id);
		myRequest = OpenRequest(HttpVerb::DELETE, path.c_str());

		bool okay = false;

		if (myRequest != NULL)
		{
			AddHeaderSessionToken(accessToken);

			if (SendRequest())
			{
				if (WinHttpReceiveResponse(myRequest, NULL))
				{
					int statusCode = GetRequestStatusCode();
					if (statusCode == 200)
					{
						cout << "map has been deleted" << endl;
						okay = true;
					}
					else if (statusCode == 302)
					{
						cout << "you do not have permission to delete the map. status code: " << statusCode << endl;
					}
					else
					{
						cout << "error trying to delete map. status code: " << statusCode << endl;
					}
				}
			}
			else
			{
				cout << "sending create map request failed" << endl;
			}

			WinHttpCloseHandle(myRequest);
			myRequest = NULL;
		}
		else
		{
			cout << "failed to create request" << endl;
		}

		return okay;
	}

	bool RequestMapDownload(int id)
	{
		wstring path = L"/MapServer/rest/maps/" + to_wstring(id);
		myRequest = OpenRequest(HttpVerb::GET, path.c_str());

		bool found = false;

		if (myRequest != NULL)
		{
			if (SendRequest())
			{
				if (WinHttpReceiveResponse(myRequest, NULL))
				{
					int statusCode = GetRequestStatusCode();
					if (statusCode == 200)
					{
						cout << "map exists. you can download it." << endl;
						found = true;
					}
					else if (statusCode == 404)
					{
						cout << "map doesn't exist. you can't download it." << endl;
					}
					else
					{
						cout << "error checking for map existence. status code: " << statusCode << endl;
					}
				}
			}
			else
			{
				cout << "sending get request failed" << endl;
			}

			WinHttpCloseHandle(myRequest);
			myRequest = NULL;
		}
		else
		{
			cout << "failed to create request" << endl;
		}

		return found;
	}

	bool RequestGetMapList( std::vector<CustomMapEntry> &entryVec )
	{
		myRequest = OpenRequest(HttpVerb::GET, L"/MapServer/rest/maps");

		if (myRequest != NULL)
		{
			//AddHeaderSessionToken();

			if (SendRequest())
			{
				if (WinHttpReceiveResponse(myRequest, NULL))
				{
					int statusCode = GetRequestStatusCode();
					string data = GetRequestData();

					/*string headers = GetRequestHeaders();


					cout << "status code: " << statusCode << endl;
					cout << "headers: " << endl;
					cout << headers << endl;

					cout << "return data:" << endl;
					cout << data << endl;*/
					
					auto mapListJSON = json::parse(data);
					int numEntries = mapListJSON.size();
					entryVec.resize(numEntries);
					for (int i = 0; i < numEntries; ++i)
					{
						entryVec[i].Set(mapListJSON[i]);
					}

					return true;
				}
			}
			else
			{
				cout << "sending get request failed" << endl;
			}

			WinHttpCloseHandle(myRequest);
			myRequest = NULL;
		}
		else
		{
			cout << "failed to create request" << endl;
		}

		return false;
	}
};

struct S3Interface
{
	Aws::S3::S3Client *s3Client;
	string bucketName;
	static Aws::String downloadDest;

	S3Interface()
	{
		bucketName = "breakneckmaps";
		s3Client = NULL;
	}

	void InitWithCredentials(const Aws::Auth::AWSCredentials &creds)
	{
		if (s3Client != NULL)
		{
			Aws::Delete(s3Client);
			s3Client = NULL;
		}
		s3Client = Aws::New<Aws::S3::S3Client>("s3client", creds);
	}

	//removed because client doesnt have delete permissions.
	/*bool RemoveObject(const Aws::String &file)
	{
		Aws::String bucketFilePath = Aws::String(username.c_str()) + "/" + file;

		cout << "removing " << bucketFilePath << " from server" << endl;

		Aws::S3::Model::DeleteObjectRequest delReq;
		delReq.WithBucket(bucketName);
		delReq.WithKey(bucketFilePath);

		auto outcome = s3Client->DeleteObject(delReq);
		if (outcome.IsSuccess())
		{
			cout << "deleted: " << file << endl;
			return true;
		}
		else
		{
			std::cout << "delete object error: " <<
				outcome.GetError().GetExceptionName() << " " <<
				outcome.GetError().GetMessage() << std::endl;
			return false;
		}
	}*/

	void UploadObject(const Aws::String &path, const Aws::String &file, const Aws::String &username)
	{
		//must be logged in as a user to upload

		//if (!s_IsLoggedIn)
		//{
		//	cout << "tried to upload, but aren't logged in" << endl;
		//	return;
		//}

		//mapName = map;
		cout << "uploading: " << file << endl;

		Aws::String uploadPath = Aws::String(username.c_str()) + "/" + file;

		Aws::String filePath = path + file;

		Aws::S3::Model::PutObjectRequest putReq;
		putReq.WithBucket(bucketName.c_str());
		putReq.WithKey(uploadPath);

		auto fileToUpload = Aws::MakeShared<Aws::FStream>("uploadstream", filePath.c_str(), std::ios_base::in | std::ios_base::binary);

		putReq.SetBody(fileToUpload);
		//putReq.SetKey("test/" + file);
		auto outcome = s3Client->PutObject(putReq);

		if (outcome.IsSuccess())
		{
			cout << "upload " << file << " sucess!" << endl;
		}
		else
		{
			std::cout << "PutObject error: " <<
				outcome.GetError().GetExceptionName() << " " <<
				outcome.GetError().GetMessage() << std::endl;
		}
	}

	void DownloadObject(const Aws::String &downloadPath, const Aws::String &key, const Aws::String &file)
	{
		//assumes its a map
		downloadDest = downloadPath + file;
		cout << "downloading: " << file << endl;

		string *test = new string;

		Aws::S3::Model::GetObjectRequest getReq;
		getReq.WithBucket(bucketName.c_str());
		getReq.WithKey(key);//"gateblank9.brknk");
		getReq.SetResponseStreamFactory([]() {return Aws::New<Aws::FStream>("mapfstream", downloadDest.c_str(), std::ios_base::in | std::ios_base::out | std::ios_base::trunc | std::ios_base::binary); });

		auto outcome = s3Client->GetObject(getReq);

		if (outcome.IsSuccess())
		{
			cout << "download sucess!" << endl;
		}
		else
		{
			std::cout << "GetObject error: " <<
				outcome.GetError().GetExceptionName() << " " <<
				outcome.GetError().GetMessage() << std::endl;
		}
	}
};
Aws::String S3Interface::downloadDest = "";

struct CognitoInterface
{
	std::shared_ptr<Aws::CognitoIdentityProvider::CognitoIdentityProviderClient> identityProviderClient;
	std::shared_ptr<Aws::CognitoIdentity::CognitoIdentityClient> identityClient;
	bool isLoggedIn;
	string tokenType;
	string accessToken;
	string IDToken;
	string refreshToken;
	string username;
	Aws::Auth::AWSCredentials currCreds;

	const char * const &GetAccessToken()
	{
		assert(isLoggedIn);
		return accessToken.c_str();
	}

	CognitoInterface()
	{
		isLoggedIn = false;
	}

	void InitWithCredentials(const Aws::Auth::AWSCredentials &creds)
	{
		if (identityProviderClient == NULL)
		{
			currCreds = creds;
			Aws::Client::ClientConfiguration clientConfiguration;
			clientConfiguration.region = Aws::Region::US_EAST_1;

			if (identityProviderClient != NULL)
			{
				identityProviderClient = NULL; //deletes because its a shared_ptr
			}
			identityProviderClient = Aws::MakeShared<Aws::CognitoIdentityProvider::
				CognitoIdentityProviderClient>("CognitoIdentityProviderClient", currCreds, clientConfiguration);

			identityClient = Aws::MakeShared<Aws::CognitoIdentity::CognitoIdentityClient>("clienttest", currCreds, clientConfiguration);
		}
		else
		{
			cout << "cognito interface already initialized!";
			assert(0);
		}
	}

	bool TryLogIn(const std::string &user, const std::string &pass)
	{
		if (isLoggedIn)
		{
			assert(0);
			return false;
		}

		Aws::Http::HeaderValueCollection authParameters{
			{ "USERNAME", user.c_str() },
			{ "PASSWORD", pass.c_str() }
		};

		Aws::CognitoIdentityProvider::Model::InitiateAuthRequest initiateAuthRequest;
		initiateAuthRequest.SetClientId(APP_CLIENT_ID);
		initiateAuthRequest.SetAuthFlow(Aws::CognitoIdentityProvider::Model::AuthFlowType::USER_PASSWORD_AUTH);
		initiateAuthRequest.SetAuthParameters(authParameters);
		Aws::CognitoIdentityProvider::Model::InitiateAuthOutcome initiateAuthOutcome{ identityProviderClient->InitiateAuth(initiateAuthRequest) };

		if (initiateAuthOutcome.IsSuccess())
		{
			Aws::CognitoIdentityProvider::Model::InitiateAuthResult initiateAuthResult{ initiateAuthOutcome.GetResult() };
			auto challengeName = initiateAuthResult.GetChallengeName();
			cout << "challengeName: " << (int)challengeName << endl;
			if (challengeName == Aws::CognitoIdentityProvider::Model::ChallengeNameType::NOT_SET)
			{
				// for this code sample, this is what we expect, there should be no further challenges
				// there are more complex options, for example requiring the user to reset the password the first login
				// or using a more secure password transfer mechanism which will be covered in later examples
				Aws::CognitoIdentityProvider::Model::AuthenticationResultType authenticationResult = initiateAuthResult.GetAuthenticationResult();
				cout << endl << "Congratulations, you have successfully signed in as user: " << user << endl;
				/*cout << "\tToken Type: " << authenticationResult.GetTokenType() << endl;
				cout << "\tAccess Token: " << authenticationResult.GetAccessToken().substr(0, 20) << " ..." << endl;
				cout << "\tExpires in " << authenticationResult.GetExpiresIn() << " seconds" << endl;
				cout << "\tID Token: " << authenticationResult.GetIdToken().substr(0, 20) << " ..." << endl;
				cout << "\tRefresh Token: " << authenticationResult.GetRefreshToken().substr(0, 20) << " ..." << endl;*/

				isLoggedIn = true;
				tokenType = authenticationResult.GetTokenType().c_str();
				accessToken = authenticationResult.GetAccessToken().c_str();
				IDToken = authenticationResult.GetIdToken().c_str();
				refreshToken = authenticationResult.GetRefreshToken().c_str();

				Aws::CognitoIdentity::Model::GetIdRequest idreq;
				idreq.AddLogins("cognito-idp.us-east-1.amazonaws.com/us-east-1_6v9AExXS8", IDToken.c_str());
				idreq.SetAccountId("942521585968");
				idreq.SetIdentityPoolId("us-east-1:e8840b78-d9e3-4c03-8d6b-a9bdd5833fbd");
				auto getidoutcome = identityClient->GetId(idreq);
				Aws::String identityID;
				if (getidoutcome.IsSuccess())
				{
					auto idresult = getidoutcome.GetResult();
					identityID = idresult.GetIdentityId();
				}
				else
				{
					cout << "GET ID OUTCOME FAILED" << endl;
				}

				Aws::CognitoIdentity::Model::GetCredentialsForIdentityRequest cred_request;

				cred_request.AddLogins("cognito-idp.us-east-1.amazonaws.com/us-east-1_6v9AExXS8", IDToken.c_str());
				cred_request.SetIdentityId(identityID);

				auto response = identityClient->GetCredentialsForIdentity(cred_request);

				auto temp = response.GetResultWithOwnership().GetCredentials();
				Aws::Auth::AWSCredentials creds(temp.GetAccessKeyId(), temp.GetSecretKey(), temp.GetSessionToken());
				currCreds = creds;

				username = user;
				return true;
			}
			else if (challengeName == Aws::CognitoIdentityProvider::Model::ChallengeNameType::NEW_PASSWORD_REQUIRED)
			{
				Aws::CognitoIdentityProvider::Model::RespondToAuthChallengeRequest challengeResponse;
				challengeResponse.SetChallengeName(challengeName);
				challengeResponse.SetClientId(APP_CLIENT_ID);
				challengeResponse.SetSession(initiateAuthResult.GetSession());
				challengeResponse.AddChallengeResponses("USERNAME", username.c_str());
				challengeResponse.AddChallengeResponses("NEW_PASSWORD", pass.c_str());
				auto responseOutcome = identityProviderClient->RespondToAuthChallenge(challengeResponse);
				if (responseOutcome.IsSuccess())
				{
					cout << "response succeeded" << endl;
				}
				else
				{
					cout << "response failed" << endl;
				}
			}
		}
		else
		{
			Aws::Client::AWSError<Aws::CognitoIdentityProvider::CognitoIdentityProviderErrors> error = initiateAuthOutcome.GetError();
			cout << "Error logging in: " << error.GetMessage() << endl << endl;
		}

		return false;
	}
};

struct CustomMapClient
{
	CustomMapClient()
	{
		Aws::Utils::Logging::LogLevel logLevel{ Aws::Utils::Logging::LogLevel::Trace };
		//options.loggingOptions.logLevel = logLevel;
		AWSSDKOptions.loggingOptions.logger_create_fn = [logLevel] {return std::make_shared<Aws::Utils::Logging::ConsoleLogSystem>(logLevel); };
		Aws::InitAPI(AWSSDKOptions);
	}

	~CustomMapClient()
	{
		Cleanup();
	}

	void AnonymousInit()
	{
		Aws::Auth::CognitoCachingAnonymousCredentialsProvider *anonCredProvider = new Aws::Auth::CognitoCachingAnonymousCredentialsProvider(
			"942521585968", "us-east-1:e8840b78-d9e3-4c03-8d6b-a9bdd5833fbd");

		Aws::Auth::AWSCredentials anonCreds = anonCredProvider->GetAWSCredentials();

		s3Interface.InitWithCredentials(anonCreds);
		cognitoInterface.InitWithCredentials(anonCreds);

		serverConn.ConnectToServer();
	}

	void Cleanup()
	{
		serverConn.CleanupServerConnection();
		Aws::ShutdownAPI(AWSSDKOptions);
	}

	bool AttemptDeleteMapFromServer(CustomMapEntry &entry)
	{
		if (IsLoggedIn())
		{
			if (serverConn.RequestMapDeletion(entry.id, cognitoInterface.GetAccessToken()))
			{
				cout << "map " << entry.name << " by user: " << entry.creatorName << " has been removed" << endl;
				return true;
			}
			else
			{
				cout << "failed to remove map: " << entry.name << " by user: " << entry.creatorName << endl;
			}
		}

		return false;
	}

	bool AttemptUploadMapToServer(const std::string &path, const std::string &mapName)
	{
		if (IsLoggedIn())
		{
			if (serverConn.RequestMapUpload(mapName, cognitoInterface.GetAccessToken()))
			{
				CustomMapEntry entry;
				entry.name = mapName;
				string file = entry.GetMapFileName();
				s3Interface.UploadObject(path.c_str(), file.c_str(), cognitoInterface.username.c_str()); //assumed to work for now..
				return true;
			}
		}

		return false;
	}

	bool AttemptDownloadMapFromServer(const std::string &downloadPath, CustomMapEntry &entry)
	{
		if (serverConn.RequestMapDownload(entry.id))
		{
			string key = entry.CreateKey();
			string file = entry.GetMapFileName();
			s3Interface.DownloadObject(downloadPath.c_str(), key.c_str(), file.c_str());
			return true;
		}

		return false;
	}

	bool AttempGetMapListFromServer()
	{
		return serverConn.RequestGetMapList(mapEntries);
	}
	
	void PrintMapEntries()
	{
		cout << "Listing all maps: " << endl;
		int numEntries = mapEntries.size();
		for (int i = 0; i < numEntries; ++i)
		{
			cout << "map: " << mapEntries[i].name << "   by user: " << mapEntries[i].creatorName << endl;
		}
	}

	bool AttemptUserLogin(const std::string &user, const std::string &pass)
	{
		if (!IsLoggedIn())
		{
			if (cognitoInterface.TryLogIn("test", "Shephard123~"))
			{
				s3Interface.InitWithCredentials(cognitoInterface.currCreds);
				return true;
			}
		}
		return false;
	}

	bool IsLoggedIn()
	{
		return cognitoInterface.isLoggedIn;
	}

	std::vector<CustomMapEntry> mapEntries;

private:
	S3Interface s3Interface;
	ServerConnection serverConn;
	CognitoInterface cognitoInterface;
	Aws::SDKOptions AWSSDKOptions;
	
};

int main()
{
	CustomMapClient customMapClient;
	customMapClient.AnonymousInit();

	//customMapClient.AttemptUserLogin("test", "Shephard123~");
	
	//customMapClient.AttemptUploadMapToServer("MyMaps/", "gateblank8");
	//customMapClient.AttempGetMapListFromServer();

	//customMapClient.AttemptDeleteMapFromServer(customMapClient.mapEntries[1]);

	customMapClient.AttempGetMapListFromServer();

	customMapClient.PrintMapEntries();

	cout << endl << "done" << endl;
	int x;
	cin >> x;
}