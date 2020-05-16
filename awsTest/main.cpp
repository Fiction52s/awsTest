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
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
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

static Aws::S3::S3Client *s3Client = NULL;

const char bucketName[] = "breakneckmaps";

static Aws::String downloadDest;


static std::shared_ptr<Aws::CognitoIdentityProvider::CognitoIdentityProviderClient> s_AmazonCognitoClient;
static std::shared_ptr<Aws::CognitoIdentity::CognitoIdentityClient> s_c;
static bool s_IsLoggedIn = false;
static string s_TokenType;
static string s_AccessToken;
static string s_IDToken;
static string s_RefreshToken;
static string sessionHeaderName = "Session-Token:";
static LPCWSTR ContentType_JSON = L"Content-Type:application/json";
static string username;

//static Aws::CognitoIdentityProvider::Model::AuthenticationResultType authResult;
static bool loggedIn = false;
HINTERNET myConnection = NULL;
HINTERNET mySession = NULL;
HINTERNET myRequest = NULL;

using json = nlohmann::json;

struct MapEntry
{
	int id;
	string name;
	string creatorName;

	//json jsonObj;

	MapEntry()
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

	//MapEntry(const std::string &p_name, const std::string &p_creatorName)
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

static std::vector<MapEntry> mapEntries;

namespace Verb
{
	static LPCWSTR GET = L"GET";
	static LPCWSTR POST = L"POST";
	static LPCWSTR PUT = L"PUT";
	static LPCWSTR DELETE = L"DELETE";
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
	if (myConnection != NULL ) WinHttpCloseHandle(myConnection);
	if (mySession != NULL ) WinHttpCloseHandle(mySession);

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

	if (mySession != NULL )
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

bool AddHeaderSessionToken()
{
	string sessionHeader = sessionHeaderName + s_AccessToken;
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

bool RequestMapUpload( const string &mapName )
{
	myRequest = OpenRequest(Verb::POST, L"/MapServer/rest/maps");

	bool okay = false;
	if (myRequest != NULL )
	{
		AddHeaderContentTypeJSON();
		AddHeaderSessionToken();

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

bool RequestMapDeletion(int id)
{
	wstring path = L"/MapServer/rest/maps/" + to_wstring(id);
	myRequest = OpenRequest(Verb::DELETE, path.c_str());

	bool okay = false;

	if (myRequest != NULL)
	{
		AddHeaderSessionToken();

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

bool RequestMapDownload( int id )
{
	wstring path = L"/MapServer/rest/maps/" + to_wstring(id);
	myRequest = OpenRequest(Verb::GET, path.c_str());

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

void RequestGetMapList()
{
	myRequest = OpenRequest(Verb::GET, L"/MapServer/rest/maps");

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
				cout << "Listing all maps on server: " << endl;

				auto mapListJSON = json::parse(data);
				//std::vector<MapEntry> mapEntries;
				int numEntries = mapListJSON.size();
				mapEntries.resize(numEntries);
				for (int i = 0; i < numEntries; ++i)
				{
					mapEntries[i].Set(mapListJSON[i]);
				}

				for (int i = 0; i < numEntries; ++i)
				{
					cout << "map: " << mapEntries[i].name << "   by user: " << mapEntries[i].creatorName << endl;
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
}

bool RemoveObject(const Aws::String &file)
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
}

void UploadObject(const Aws::String &path, const Aws::String &file)
{
	if (!s_IsLoggedIn)
	{
		cout << "tried to upload, but aren't logged in" << endl;
		return;
	}

	//mapName = map;
	cout << "uploading: " << file << endl;

	Aws::String uploadPath = Aws::String(username.c_str()) + "/" + file;

	Aws::String filePath = path + file;

	Aws::S3::Model::PutObjectRequest putReq;
	putReq.WithBucket(bucketName);
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

void DownloadObject( const Aws::String &downloadPath, const Aws::String &key, const Aws::String &file )
{
	//assumes its a map
	downloadDest =  downloadPath + file;
	cout << "downloading: " << file << endl;

	Aws::S3::Model::GetObjectRequest getReq;
	getReq.WithBucket(bucketName);
	getReq.WithKey(key);//"gateblank9.brknk");
	getReq.SetResponseStreamFactory([]() {return Aws::New<Aws::FStream>("mapfstream", downloadDest.c_str() , std::ios_base::in | std::ios_base::out | std::ios_base::trunc); });

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

void CreateClientsWithAnonymousCredentials()
{
	Aws::Auth::CognitoCachingAnonymousCredentialsProvider *anonCred = new Aws::Auth::CognitoCachingAnonymousCredentialsProvider(
		"942521585968", "us-east-1:e8840b78-d9e3-4c03-8d6b-a9bdd5833fbd");

	if (s3Client != NULL)
	{
		Aws::Delete(s3Client);
		s3Client = NULL;
	}
	s3Client = Aws::New<Aws::S3::S3Client>("s3client", anonCred->GetAWSCredentials());


	Aws::Client::ClientConfiguration clientConfiguration;
	clientConfiguration.region = Aws::Region::US_EAST_1;

	if (s_AmazonCognitoClient != NULL)
	{
		s_AmazonCognitoClient = NULL; //deletes because its a shared_ptr
	}
	s_AmazonCognitoClient = Aws::MakeShared<Aws::CognitoIdentityProvider::
		CognitoIdentityProviderClient>("CognitoIdentityProviderClient", anonCred->GetAWSCredentials(), clientConfiguration);

	s_c = Aws::MakeShared<Aws::CognitoIdentity::CognitoIdentityClient>("clienttest", anonCred->GetAWSCredentials(), clientConfiguration);
}

void TestSignIn( const std::string &user, const std::string &pass )
{
	username = "test";
	Aws::String password = "Shephard123~";

	Aws::Http::HeaderValueCollection authParameters{
		{ "USERNAME", username.c_str() },
		{ "PASSWORD", password }
	};

	Aws::CognitoIdentityProvider::Model::InitiateAuthRequest initiateAuthRequest;
	initiateAuthRequest.SetClientId(APP_CLIENT_ID);
	initiateAuthRequest.SetAuthFlow(Aws::CognitoIdentityProvider::Model::AuthFlowType::USER_PASSWORD_AUTH);
	initiateAuthRequest.SetAuthParameters(authParameters);
	Aws::CognitoIdentityProvider::Model::InitiateAuthOutcome initiateAuthOutcome{ s_AmazonCognitoClient->InitiateAuth(initiateAuthRequest) };

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
			cout << endl << "Congratulations, you have successfully signed in!" << endl;
			cout << "\tToken Type: " << authenticationResult.GetTokenType() << endl;
			cout << "\tAccess Token: " << authenticationResult.GetAccessToken().substr(0, 20) << " ..." << endl;
			cout << "\tExpires in " << authenticationResult.GetExpiresIn() << " seconds" << endl;
			cout << "\tID Token: " << authenticationResult.GetIdToken().substr(0, 20) << " ..." << endl;
			cout << "\tRefresh Token: " << authenticationResult.GetRefreshToken().substr(0, 20) << " ..." << endl;

			s_IsLoggedIn = true;
			s_TokenType = authenticationResult.GetTokenType().c_str();
			s_AccessToken = authenticationResult.GetAccessToken().c_str();
			s_IDToken = authenticationResult.GetIdToken().c_str();
			s_RefreshToken = authenticationResult.GetRefreshToken().c_str();

			Aws::CognitoIdentity::Model::GetIdRequest idreq;
			idreq.AddLogins("cognito-idp.us-east-1.amazonaws.com/us-east-1_6v9AExXS8", s_IDToken.c_str());
			idreq.SetAccountId("942521585968");
			idreq.SetIdentityPoolId("us-east-1:e8840b78-d9e3-4c03-8d6b-a9bdd5833fbd");
			auto getidoutcome = s_c->GetId(idreq);
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

			cred_request.AddLogins("cognito-idp.us-east-1.amazonaws.com/us-east-1_6v9AExXS8", s_IDToken.c_str());//s_IDToken.c_str());
			cred_request.SetIdentityId(identityID);

			auto response = s_c->GetCredentialsForIdentity(cred_request);

			auto temp = response.GetResultWithOwnership().GetCredentials();
			Aws::Auth::AWSCredentials creds(temp.GetAccessKeyId(), temp.GetSecretKey(), temp.GetSessionToken());
			//auto creds = response.getresult

			if (s3Client != NULL)
			{
				Aws::Delete(s3Client);
				s3Client = NULL;
			}

			s3Client = Aws::New<Aws::S3::S3Client>("s3client", creds);

			//DownloadObject("gateblank9.brknk");
		}
		else if (challengeName == Aws::CognitoIdentityProvider::Model::ChallengeNameType::NEW_PASSWORD_REQUIRED)
		{
			Aws::CognitoIdentityProvider::Model::RespondToAuthChallengeRequest challengeResponse;
			challengeResponse.SetChallengeName(challengeName);
			challengeResponse.SetClientId(APP_CLIENT_ID);
			challengeResponse.SetSession(initiateAuthResult.GetSession());
			challengeResponse.AddChallengeResponses("USERNAME", username.c_str());
			challengeResponse.AddChallengeResponses("NEW_PASSWORD", password);
			auto responseOutcome = s_AmazonCognitoClient->RespondToAuthChallenge(challengeResponse);
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
}

bool AttemptMapDeletionFromServer(MapEntry &entry)
{
	if (RequestMapDeletion(entry.id))
	{
		cout << "map " << entry.name << " by user: " << entry.creatorName << " has been removed" << endl;
		return true;
	}
	else
	{
		cout << "failed to remove map: " << entry.name << " by user: " << entry.creatorName << endl;
		return false;
	}
}

bool AttemptMapUploadToServer( const std::string &path, const std::string &mapName)
{
	if (RequestMapUpload(mapName))
	{
		MapEntry entry;
		entry.name = mapName;
		string file = entry.GetMapFileName();
		UploadObject(path.c_str(), file.c_str()); //assumed to work for now..
		return true;
	}

	return false;
}

bool AttemptMapDownloadFromServer( const std::string &downloadPath, MapEntry &entry)
{
	if (RequestMapDownload(entry.id))
	{
		string key = entry.CreateKey();
		string file = entry.GetMapFileName();
		DownloadObject( downloadPath.c_str(), key.c_str(), file.c_str());
		return true;
	}

	return false;
}

void RunCognitoTest()
{
	TestSignIn( "test", "Shephard123~" );

	if (s_IsLoggedIn)
	{
		AttemptMapUploadToServer("MyMaps/", "gateblank9");

		RequestGetMapList();

		//AttemptMapDeletionFromServer(mapEntries[0]);

		//AttemptMapDownloadFromServer("DownloadedMaps/", mapEntries[0]);
	}
}

static Aws::SDKOptions AWSSDKOptions;
void InitAWS()
{
	Aws::Utils::Logging::LogLevel logLevel{ Aws::Utils::Logging::LogLevel::Trace };
	//options.loggingOptions.logLevel = logLevel;
	AWSSDKOptions.loggingOptions.logger_create_fn = [logLevel] {return std::make_shared<Aws::Utils::Logging::ConsoleLogSystem>(logLevel); };
	Aws::InitAPI(AWSSDKOptions);
}

void CleanupAWS()
{
	Aws::ShutdownAPI(AWSSDKOptions);
}

int main()
{
	InitAWS();
	
	CreateClientsWithAnonymousCredentials();
	ConnectToServer();

	RequestGetMapList();
	//RunCognitoTest();

	CleanupServerConnection();

	CleanupAWS();

	cout << endl << "done" << endl;
	int x;
	cin >> x;
}