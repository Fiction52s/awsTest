#include <iostream>
#include <aws/core/Aws.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/Bucket.h>
#include <aws/cognito-identity/CognitoIdentityClient.h>
#include <aws/cognito-identity/CognitoIdentity_EXPORTS.h>
#include <aws/cognito-identity/CognitoIdentityEndpoint.h>
#include <aws/cognito-identity/CognitoIdentityErrorMarshaller.h>
#include <aws/cognito-identity/CognitoIdentityErrors.h>
#include <aws/cognito-identity/CognitoIdentityRequest.h>
#include <aws/cognito-idp/CognitoIdentityProviderClient.h>
#include <aws/cognito-idp/model/InitiateAuthRequest.h>
#include <aws/cognito-idp/model/ChangePasswordRequest.h>
#include <aws/cognito-idp/model/RespondToAuthChallengeRequest.h>
#include <aws/cognito-identity/model/CognitoIdentityProvider.h>
#include <aws/core/utils/logging/ConsoleLogSystem.h>
#include <aws/identity-management/auth/CognitoCachingCredentialsProvider.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/core/utils/memory/stl/AWSStreamFwd.h>
#include <fstream>

#include <Windows.h>
#include <winhttp.h>

#include "ClientID.h"

#undef GetObject
#undef GetMessage


using namespace std;
using namespace Aws;
using namespace Aws::CognitoIdentity::Model;

Aws::S3::S3Client *s3Client;

const char bucketName[] = "breakneckmapbucketeast";

static Aws::String mapName;

static std::shared_ptr<Aws::CognitoIdentityProvider::CognitoIdentityProviderClient> s_AmazonCognitoClient;
static bool s_IsLoggedIn = false;
static string s_TokenType;
static string s_AccessToken;
static string s_IDToken;
static string s_RefreshToken;

//static Aws::CognitoIdentityProvider::Model::AuthenticationResultType authResult;
static bool loggedIn = false;

//s_TokenType = authenticationResult.GetTokenType();
//s_AccessToken = authenticationResult.GetAccessToken();
//s_IDToken = authenticationResult.GetIdToken();
//s_RefreshToken = authenticationResult.GetRefreshToken();


void ListObjects()
{
	cout << "listing: " << endl;
	Aws::S3::Model::ListObjectsRequest listReq;
	listReq.WithBucket( bucketName );

	auto outcome = s3Client->ListObjects(listReq);

	if (outcome.IsSuccess())
	{
		Aws::Vector<Aws::S3::Model::Object> object_list =
			outcome.GetResult().GetContents();

		for (auto const &s3_object : object_list)
		{
			std::cout << "object: " << s3_object.GetKey() << std::endl;
		}
	}
	else
	{
		std::cout << "ListObjects error: " <<
			outcome.GetError().GetExceptionName() << " " <<
			outcome.GetError().GetMessage() << std::endl;
	}
}

void UploadObject(const Aws::String &file)
{
	//mapName = map;
	cout << "uploading: " << file << endl;

	Aws::S3::Model::PutObjectRequest putReq;
	putReq.WithBucket(bucketName);
	putReq.WithKey(file);

	auto fileToUpload = Aws::MakeShared<Aws::FStream>("uploadstream", file.c_str(), std::ios_base::in | std::ios_base::binary);

	putReq.SetBody(fileToUpload);

	auto outcome = s3Client->PutObject(putReq);

	if (outcome.IsSuccess())
	{
		cout << "upload sucess!" << endl;
	}
	else
	{
		std::cout << "PutObject error: " <<
			outcome.GetError().GetExceptionName() << " " <<
			outcome.GetError().GetMessage() << std::endl;
	}
}

//std::wstring s2ws(const std::string& s)
//{
//	int len;
//	int slength = (int)s.length() + 1;
//	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
//	wchar_t* buf = new wchar_t[len];
//	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
//	std::wstring r(buf);
//	delete[] buf;
//	return r;
//}

HINTERNET myConnection = NULL;
HINTERNET mySession = NULL;
HINTERNET myRequest = NULL;
void CleanupServerConnection()
{
	//if (myRequest) WinHttpCloseHandle(myRequest);
	if (myConnection != NULL ) WinHttpCloseHandle(myConnection);
	if (mySession != NULL ) WinHttpCloseHandle(mySession);

	//myRequest = NULL;
	myConnection = NULL;
	mySession = NULL;
}

void ConnectToServer()
{
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	BOOL  bResults = FALSE;

	mySession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (mySession != NULL )
	{
		myConnection = WinHttpConnect(mySession, L"localhost",
			8080, 0);
	}	
}

bool RequestMapUpload( const string &mapName )
{
	if (myConnection != NULL )
		myRequest = WinHttpOpenRequest(myConnection, L"POST", L"/MapServer/rest/maps",
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	if (myRequest != NULL )
	{
		string sessionHeaderName = "Session-Token:";
		string sessionHeader = sessionHeaderName + s_AccessToken;
		wstring wideSessionHeader = wstring(sessionHeader.begin(), sessionHeader.end());
		LPCWSTR wsh = wideSessionHeader.c_str();

		BOOL bResults = WinHttpAddRequestHeaders(myRequest, L"Content-Type:application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);
		BOOL bResults1 = WinHttpAddRequestHeaders(myRequest, wsh, -1, WINHTTP_ADDREQ_FLAG_ADD);

		if (!bResults || !bResults1)
		{
			cout << "failed to add a header" << endl;
		}

		string message = "{"
			"\"name\":\"" + mapName + "\""
			"}";
		const LPSTR messageBuf = (LPTSTR)message.c_str();

		// Send a request.
		
		bResults = WinHttpSendRequest(myRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0, messageBuf, strlen(messageBuf), strlen(messageBuf), 0);

		if (!bResults)
		{
			cout << "sending create map request failed" << endl;
		}
		else
		{
			bResults = WinHttpReceiveResponse(myRequest, NULL);
		}

		WinHttpCloseHandle(myRequest);
		myRequest = NULL;

		//process POST result here to see if its okay to upload

		return true;
	}
	else
	{
		cout << "failed to create request" << endl;
	}
}

bool RequestMapDeletion(const string &mapName)
{
	if (myConnection != NULL)
		myRequest = WinHttpOpenRequest(myConnection, L"DELETE", L"/MapServer/rest/maps",
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	if (myRequest != NULL)
	{
		string sessionHeaderName = "Session-Token:";
		string sessionHeader = sessionHeaderName + s_AccessToken;
		wstring wideSessionHeader = wstring(sessionHeader.begin(), sessionHeader.end());
		LPCWSTR wsh = wideSessionHeader.c_str();

		BOOL bResults = WinHttpAddRequestHeaders(myRequest, L"Content-Type:application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);
		BOOL bResults1 = WinHttpAddRequestHeaders(myRequest, wsh, -1, WINHTTP_ADDREQ_FLAG_ADD);

		if (!bResults || !bResults1)
		{
			cout << "failed to add a header" << endl;
		}

		string message = "{"
			"\"name\":\"" + mapName + "\""
			"}";
		const LPSTR messageBuf = (LPTSTR)message.c_str();

		// Send a request.

		bResults = WinHttpSendRequest(myRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0, messageBuf, strlen(messageBuf), strlen(messageBuf), 0);

		if (!bResults)
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
}

void GetMapList()
{
	if (myConnection != NULL)
		myRequest = WinHttpOpenRequest(myConnection, L"GET", L"/MapServer/rest/maps",
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	if (myRequest != NULL)
	{
		string sessionHeaderName = "Session-Token:";
		string sessionHeader = sessionHeaderName + s_AccessToken;
		wstring wideSessionHeader = wstring(sessionHeader.begin(), sessionHeader.end());
		LPCWSTR wsh = wideSessionHeader.c_str();

		BOOL bResults = WinHttpAddRequestHeaders(myRequest, L"Content-Type:application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);
		BOOL bResults1 = WinHttpAddRequestHeaders(myRequest, wsh, -1, WINHTTP_ADDREQ_FLAG_ADD);

		if (!bResults || !bResults1)
		{
			cout << "failed to add a header" << endl;
		}

		string message = "{"
			"\"name\":\"" + mapName + "\""
			"}";
		const LPSTR messageBuf = (LPTSTR)message.c_str();

		// Send a request.

		bResults = WinHttpSendRequest(myRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0, messageBuf, strlen(messageBuf), strlen(messageBuf), 0);

		if (!bResults)
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
}

void SendTokenToServer(const string & token)
{
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	// Specify an HTTP server.
	/*if (hSession)
	hConnect = WinHttpConnect(hSession, L"www.microsoft.com",
	INTERNET_DEFAULT_HTTPS_PORT, 0);*/

	/*if (hSession)
		hConnect = WinHttpConnect(hSession, L"please.eba-gkrhenjs.us-west-2.elasticbeanstalk.com",
			INTERNET_DEFAULT_HTTP_PORT, 0);*/

	if (hSession)
		hConnect = WinHttpConnect(hSession, L"localhost",
		8080, 0);
	//INTERNET_DEFAULT_HTTPS_PORT, 0);

	// Create an HTTP request handle.
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/MapServer/rest/maps",
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	string sessionHeaderName = "Session-Token:";
	string sessionHeader = sessionHeaderName + token;
	wstring wideSessionHeader = wstring(sessionHeader.begin(), sessionHeader.end());
	LPCWSTR wsh = wideSessionHeader.c_str();

	//string mapNameHeaderName = "Map-Name:";
	string mapName = "gateblank8";
	string mapFile = mapName + ".brknk";
	//string mapNameHeader = mapNameHeaderName + mapName;
	//wstring wideMapNameHeader = wstring(mapNameHeader.begin(), mapNameHeader.end());
	//LPCWSTR wmnh = wideMapNameHeader.c_str();

	//LPCWSTR test = L"Session-Token:cmon";

	if (hRequest)
	{
		BOOL bResults = WinHttpAddRequestHeaders(hRequest, L"Content-Type:application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);
		//BOOL bResults = WinHttpAddRequestHeaders(hRequest, L"Content-Type:text/plain", -1, WINHTTP_ADDREQ_FLAG_ADD);
		BOOL bResults1 = WinHttpAddRequestHeaders(hRequest, wsh, -1, WINHTTP_ADDREQ_FLAG_ADD);

		if (bResults1)
		{
			cout << "successfully added session token header" << endl;
		}
		else
		{
			cout << "failed to add session token header" << endl;
		}
		/*BOOL bResults2 = WinHttpAddRequestHeaders(hRequest, wmnh, -1, WINHTTP_ADDREQ_FLAG_ADD);
		if (bResults2)
		{
			cout << "successfully added map name header" << endl;
		}
		else
		{
			cout << "failed to add map name header" << endl;
		}*/
	}
	

	/*ifstream is;
	is.open(mapFile);
	assert(is.is_open());
	string mapFileContent((std::istreambuf_iterator<char>(is)),
		(std::istreambuf_iterator<char>()));

	const LPSTR mapFileContentLPSTR = (LPSTR)mapFileContent.c_str();*/


	//WINHTTP_FLAG_SECURE);

	/*if (hRequest)
	{
		BOOL bResults = WinHttpAddRequestHeaders( hRequest, L"content-type:application/json", -1,)
	}*/

	string message = "{"
		"\"name\":\"" + mapName + "\""
		"}";


	const LPSTR messageBuf = (LPTSTR)message.c_str();
		
	// Send a request.
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0, messageBuf, strlen(messageBuf), strlen(messageBuf), 0);


	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	// Keep checking for data until there is nothing left.
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				printf("Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());

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

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
					dwSize, &dwDownloaded))
					printf("Error %u in WinHttpReadData.\n", GetLastError());
				else
					printf("%s", pszOutBuffer);

				// Free the memory allocated to the buffer.
				delete[] pszOutBuffer;
			}
		} while (dwSize > 0);
	}


	// Report any errors.
	if (!bResults)
		printf("Error %d has occurred.\n", GetLastError());

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
}

void DeleteObject(const Aws::String &map)
{
	mapName = map;
	cout << "destroying" << endl;

	Aws::S3::Model::DeleteObjectRequest delReq;
	delReq.WithBucket(bucketName);
	delReq.WithKey(map);

	auto outcome = s3Client->DeleteObject(delReq);
	if (outcome.IsSuccess())
	{
		cout << "deleted: " << map << endl;
	}
	else
	{
		std::cout << "delete object error: " <<
			outcome.GetError().GetExceptionName() << " " <<
			outcome.GetError().GetMessage() << std::endl;
	}


}

void DownloadObject( const Aws::String &map )
{
	mapName = map;
	cout << "downloading: " << map << endl;
	Aws::S3::Model::GetObjectRequest getReq;
	getReq.WithBucket(bucketName);
	getReq.WithKey(map);//"gateblank9.brknk");
	getReq.SetResponseStreamFactory([]() {return Aws::New<Aws::FStream>("mapfstream", mapName.c_str() , std::ios_base::in | std::ios_base::out | std::ios_base::trunc); });

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

void CreateClients()
{

	//Aws::Client::ClientConfiguration clientConfiguration;
	//clientConfiguration.region = Aws::Region::US_EAST_1;

	Aws::Auth::CognitoCachingAnonymousCredentialsProvider *credentials = new Aws::Auth::CognitoCachingAnonymousCredentialsProvider(
		"942521585968", "us-east-1:e8840b78-d9e3-4c03-8d6b-a9bdd5833fbd");

	//s3Client = Aws::New<Aws::S3::S3Client>("s3client", clientConfiguration);
	s3Client = Aws::New<Aws::S3::S3Client>("s3client", credentials->GetAWSCredentials());
}

void RunBucketTest()
{
	CreateClients();

	ListObjects();

	//UploadObject("gateblank8.brknk");

	//ListObjects();
}

void TestSignIn()
{
	Aws::String username = "test";
	Aws::String password = "Shephard123~";


	Aws::Http::HeaderValueCollection authParameters{
		{ "USERNAME", username },
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
			//cout << "\tAccess Token: " << authenticationResult.GetAccessToken().substr(0, 20) << " ..." << endl;
			cout << "\tAccess Token: " << authenticationResult.GetAccessToken() << " ..." << endl;
			cout << "\tExpires in " << authenticationResult.GetExpiresIn() << " seconds" << endl;
			cout << "\tID Token: " << authenticationResult.GetIdToken().substr(0, 20) << " ..." << endl;
			cout << "\tRefresh Token: " << authenticationResult.GetRefreshToken().substr(0, 20) << " ..." << endl;

			string accessToken = authenticationResult.GetAccessToken().c_str();
			//SendTokenToServer(accessToken);
			s_IsLoggedIn = true;
			s_TokenType = authenticationResult.GetTokenType().c_str();
			s_AccessToken = authenticationResult.GetAccessToken().c_str();
			s_IDToken = authenticationResult.GetIdToken().c_str();
			s_RefreshToken = authenticationResult.GetRefreshToken().c_str();

			//if (!SendAccessTokenToServer(s_AccessToken))
			//{
			//	cout << "Unable to connect to server" << endl;
			//}
		}
		else if (challengeName == Aws::CognitoIdentityProvider::Model::ChallengeNameType::NEW_PASSWORD_REQUIRED)
		{
			Aws::CognitoIdentityProvider::Model::RespondToAuthChallengeRequest challengeResponse;
			challengeResponse.SetChallengeName(challengeName);
			challengeResponse.SetClientId(APP_CLIENT_ID);
			challengeResponse.SetSession(initiateAuthResult.GetSession());
			challengeResponse.AddChallengeResponses("USERNAME", username);
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

void RunCognitoTest()
{
	auto anonCred = Aws::MakeShared<Aws::Auth::CognitoCachingAnonymousCredentialsProvider>(
		"AnonCredentialsProvider", "942521585968", "us-east-1:e8840b78-d9e3-4c03-8d6b-a9bdd5833fbd");

	Aws::Client::ClientConfiguration clientConfiguration;
	clientConfiguration.region = Aws::Region::US_EAST_1;

	//auto cog = new Aws::CognitoIdentity::CognitoIdentityClient(credentials->GetAWSCredentials(), clientConfiguration);
	s_AmazonCognitoClient = Aws::MakeShared<Aws::CognitoIdentityProvider::
		CognitoIdentityProviderClient>("CognitoIdentityProviderClient", anonCred->GetAWSCredentials(), clientConfiguration);
	
	TestSignIn();

	if (s_IsLoggedIn)
	{
		ConnectToServer();
		bool uploadRequestResult = RequestMapDeletion("gateblank6");//RequestMapUpload("gateblank6");
		CleanupServerConnection();
	}
	/*Aws::CognitoIdentityProvider::Model::ChangePasswordRequest changePasswordRequest;
	changePasswordRequest.SetAccessToken(s_AccessToken);
	changePasswordRequest.SetPreviousPassword(currentPassword);
	changePasswordRequest.SetProposedPassword(newPassword);*/






	
}

int main()
{
	//RunDBTest();
	//const string poolID = "us-west-2_VMpmSWzDz";
	//const char* region = Aws::Region::US_WEST_2;


	Aws::SDKOptions options;
	Aws::Utils::Logging::LogLevel logLevel{ Aws::Utils::Logging::LogLevel::Trace };
	//options.loggingOptions.logLevel = logLevel;
	options.loggingOptions.logger_create_fn = [logLevel] {return std::make_shared<Aws::Utils::Logging::ConsoleLogSystem>(logLevel); };
	Aws::InitAPI(options);

	RunCognitoTest();
	//SendTokenToServer("herro");
	//s_Amz
	//
	////RunBucketTest();
	//RunDBTest();
	////RunBucketTest();

	Aws::ShutdownAPI(options);

	cout << endl << "done" << endl;
	int x;
	cin >> x;
}