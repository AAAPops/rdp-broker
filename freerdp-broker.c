/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Test Server
 *
 * Copyright 2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2011 Vic Lee
 * Copyright 2014 Norbert Federa <norbert.federa@thincast.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freerdp/config.h>

#include <errno.h>
#include <signal.h>

#include <winpr/winpr.h>
#include <winpr/crt.h>
#include <winpr/assert.h>
#include <winpr/ssl.h>
#include <winpr/synch.h>
#include <winpr/file.h>
#include <winpr/string.h>
#include <winpr/path.h>
#include <winpr/image.h>
#include <winpr/winsock.h>

#include <freerdp/streamdump.h>
#include <freerdp/transport_io.h>

//#include <freerdp/channels/wtsvc.h>
//#include <freerdp/channels/channels.h>
//#include <freerdp/channels/drdynvc.h>

#include <freerdp/freerdp.h>
#include <freerdp/constants.h>
#include <freerdp/settings.h>
#include <freerdp/redirection.h>

#include "freerdp-broker.h"
#include "nng_client/nng-client.h"

#include <freerdp/log.h>
#define TAG SERVER_TAG("sample")


struct server_info
{
	//const char* test_pcap_file;
	const char* cert;
	const char* key;
};

static void test_peer_context_free(freerdp_peer* client, rdpContext* ctx)
{
	testPeerContext* context = (testPeerContext*)ctx;

	WINPR_UNUSED(client);

	if (context)
	{
		Stream_Free(context->s, TRUE);
		free(context->bg_data);

		if (context->debug_channel)
			WTSVirtualChannelClose(context->debug_channel);
	}
}

static BOOL test_peer_context_new(freerdp_peer* client, rdpContext* ctx)
{
	testPeerContext* context = (testPeerContext*)ctx;

	WINPR_ASSERT(client);
	WINPR_ASSERT(context);
	WINPR_ASSERT(ctx->settings);

	if (!(context->s = Stream_New(NULL, 65536)))
		goto fail;

	return TRUE;
fail:
	test_peer_context_free(client, ctx);
	return FALSE;
}

static BOOL test_peer_init(freerdp_peer* client)
{
	WINPR_ASSERT(client);

	client->ContextSize = sizeof(testPeerContext);
	client->ContextNew = test_peer_context_new;
	client->ContextFree = test_peer_context_free;
	return freerdp_peer_context_new(client);
}


static BOOL tf_peer_post_connect(freerdp_peer* client)
{
	testPeerContext* context = NULL;
	rdpSettings* settings = NULL;

    const char* Username;
    const char* Domain;
    const char* Passwd;

	WINPR_ASSERT(client);

	context = (testPeerContext*)client->context;
	WINPR_ASSERT(context);

	settings = client->context->settings;
	WINPR_ASSERT(settings);

	/**
	 * This callback is called when the entire connection sequence is done, i.e. we've received the
	 * Font List PDU from the client and sent out the Font Map PDU.
	 * The server may start sending graphics output and receiving keyboard/mouse input after this
	 * callback returns.
	 */
	WLog_DBG(TAG, "Client %s is activated (osMajorType %" PRIu32 " osMinorType %" PRIu32 ")",
	         client->local ? "(local)" : client->hostname,
	         freerdp_settings_get_uint32(settings, FreeRDP_OsMajorType),
	         freerdp_settings_get_uint32(settings, FreeRDP_OsMinorType));

    if (freerdp_settings_get_bool(settings, FreeRDP_AutoLogonEnabled))
    {
        Username = freerdp_settings_get_string(settings, FreeRDP_Username);
        Domain = freerdp_settings_get_string(settings, FreeRDP_Domain);
        Passwd = freerdp_settings_get_string(settings, FreeRDP_Password);
        WLog_INFO(TAG, " and wants to login automatically as %s\\%s and password = '%s'",
                  Domain ? Domain : "", Username, Passwd);
        /* A real server may perform OS login here if NLA is not executed previously. */
    }

	WLog_DBG(TAG, "Using resolution requested by client.");

    const char* clientAddress = freerdp_settings_get_string(settings, FreeRDP_ClientAddress);
    const char* preconnectionBlob = freerdp_settings_get_string(settings, FreeRDP_PreconnectionBlob);
    const char* remoteAppName = freerdp_settings_get_string(settings, FreeRDP_RemoteApplicationProgram);
    const char* remoteCmdLine = freerdp_settings_get_string(settings, FreeRDP_RemoteApplicationCmdLine);
    WLog_INFO(TAG, "Client address = '%s', pcb = '%s'", clientAddress, preconnectionBlob);
    WLog_INFO(TAG, "Remote App = '%s', cmd = '%s'", remoteAppName, remoteCmdLine);

    /* !!! Insert here call to client that asks ALL agents about user with "Username"  !!! */
    char *srv_list[] = { "tcp://192.168.1.120:5555", "tcp://192.168.1.121:5555" };

    //char *target_net_addr = "192.168.1.120";
    char *target_net_addr = nng_client(Username, srv_list, 2);

    // LB_TARGET_NET_ADDRESS | LB_USERNAME | LB_DOMAIN | LB_TARGET_FQDN | LB_TARGET_NETBIOS_NAME |
    // LB_TARGET_NET_ADDRESSES |LB_CLIENT_TSV_URL |LB_SERVER_TSV_CAPABLE

    rdpRedirection *my_redir_info = redirection_new();
    redirection_set_session_id(my_redir_info, 0x03);


    redirection_set_string_option(my_redir_info, LB_TARGET_NET_ADDRESS, target_net_addr);

    //char *username = "a1";
    redirection_set_string_option(my_redir_info, LB_USERNAME, Username);

    redirection_set_flags(my_redir_info, LB_TARGET_NET_ADDRESS | LB_USERNAME);

    //if ( strcmp(Username, "a1") == 0 ) {
    //    WLog_INFO(TAG, "===> Wait for 15 sec. for user ''", Username);
    //    sleep(15);
    //}

    client->SendServerRedirection(client, my_redir_info);
	/* A real server should tag the peer as activated here and start sending updates in main loop. */

	/* Return FALSE here would stop the execution of the peer main loop. */
	return TRUE;
}


static DWORD WINAPI test_peer_mainloop(LPVOID arg)
{
	BOOL rc = 0;
	DWORD error = CHANNEL_RC_OK;
	HANDLE handles[MAXIMUM_WAIT_OBJECTS] = { 0 };
	DWORD count = 0;
	DWORD status = 0;
	testPeerContext* context = NULL;
	struct server_info* info = NULL;
	rdpSettings* settings = NULL;
	freerdp_peer* client = (freerdp_peer*)arg;

	WINPR_ASSERT(client);

	info = client->ContextExtra;
	WINPR_ASSERT(info);

	if (!test_peer_init(client))
	{
		freerdp_peer_free(client);
		return 0;
	}

	/* Initialize the real server settings here */
	WINPR_ASSERT(client->context);
	settings = client->context->settings;
	WINPR_ASSERT(settings);


	rdpPrivateKey* key = freerdp_key_new_from_file(info->key);
	if (!key)
		goto fail;
	if (!freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerRsaKey, key, 1))
		goto fail;
	rdpCertificate* cert = freerdp_certificate_new_from_file(info->cert);
	if (!cert)
		goto fail;
	if (!freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerCertificate, cert, 1))
		goto fail;

	if (!freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, TRUE))
		goto fail;
	if (!freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, TRUE))
		goto fail;
	if (!freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, FALSE))
		goto fail;
    /*  ENCRYPTION_LEVEL_HIGH; */
    /*  ENCRYPTION_LEVEL_LOW; */
    /*  ENCRYPTION_LEVEL_FIPS; */
    if (!freerdp_settings_set_uint32(settings, FreeRDP_EncryptionLevel, ENCRYPTION_LEVEL_CLIENT_COMPATIBLE))
		goto fail;


	client->PostConnect = tf_peer_post_connect;
	//client->Activate = tf_peer_activate;

	WINPR_ASSERT(client->context);
	WINPR_ASSERT(client->Initialize);
	rc = client->Initialize(client);
	if (!rc)
		goto fail;

	context = (testPeerContext*)client->context;
	WINPR_ASSERT(context);

	WLog_INFO(TAG, "We've got a client %s", client->local ? "(local)" : client->hostname);

	while (1)
	{
		count = 0;
		{
			WINPR_ASSERT(client->GetEventHandles);
			DWORD tmp = client->GetEventHandles(client, &handles[count], 32 - count);
            //WLog_INFO(TAG, "===> tmp = %d,  count = %d", tmp, count);
			if (tmp == 0)
			{
				WLog_ERR(TAG, "Failed to get FreeRDP transport event handles");
				break;
			}

			count += tmp;
		}

        status = WaitForMultipleObjects(count, handles, FALSE, INFINITE);

		if (status == WAIT_FAILED)
		{
			WLog_ERR(TAG, "WaitForMultipleObjects failed (errno: %d)", errno);
			break;
		}

		WINPR_ASSERT(client->CheckFileDescriptor);
		if (client->CheckFileDescriptor(client) != TRUE)
			break;
	}

	WLog_INFO(TAG, "Client %s disconnected.", client->local ? "(local)" : client->hostname);

	WINPR_ASSERT(client->Disconnect);
	client->Disconnect(client);
fail:
	freerdp_peer_context_free(client);
	freerdp_peer_free(client);
	return error;
}

static BOOL test_peer_accepted(freerdp_listener* instance, freerdp_peer* client)
{
	HANDLE hThread = NULL;
	struct server_info* info = NULL;

	WINPR_UNUSED(instance);

	WINPR_ASSERT(instance);
	WINPR_ASSERT(client);

	info = instance->info;
	client->ContextExtra = info;

	if (!(hThread = CreateThread(NULL, 0, test_peer_mainloop, (void*)client, 0, NULL)))
		return FALSE;
    WLog_INFO(TAG, "===> CreateThread(test_peer_mainloop) = TRUE");

	CloseHandle(hThread);
	return TRUE;
}

static void test_server_mainloop(freerdp_listener* instance)
{
	HANDLE handles[32] = { 0 };
	DWORD count = 0;
	DWORD status = 0;

	WINPR_ASSERT(instance);
	while (1)
	{
		WINPR_ASSERT(instance->GetEventHandles);
		count = instance->GetEventHandles(instance, handles, 32);

		if (0 == count)
		{
			WLog_ERR(TAG, "Failed to get FreeRDP event handles");
			break;
		}

        //WLog_INFO(TAG, "===> WaitForMultipleObjects(1)");
        //WLog_INFO(TAG, "===> count = %d", count);
		status = WaitForMultipleObjects(count, handles, FALSE, INFINITE);
        //WLog_INFO(TAG, "===> WaitForMultipleObjects(2)");

		if (WAIT_FAILED == status)
		{
			WLog_ERR(TAG, "select failed");
			break;
		}

		WINPR_ASSERT(instance->CheckFileDescriptor);
		if (instance->CheckFileDescriptor(instance) != TRUE)
		{
			WLog_ERR(TAG, "Failed to check FreeRDP file descriptor");
			break;
		}
	}

	WINPR_ASSERT(instance->Close);
	instance->Close(instance);
}

static const struct
{
	const char spcap[7];
	const char sfast[7];
	const char sport[7];
	const char slocal_only[13];
	const char scert[7];
	const char skey[6];
} options = { "--pcap=", "--fast", "--port=", "--local-only", "--cert=", "--key=" };

WINPR_ATTR_FORMAT_ARG(2, 0)
static void print_entry(FILE* fp, WINPR_FORMAT_ARG const char* fmt, const char* what, size_t size)
{
	char buffer[32] = { 0 };
	strncpy(buffer, what, MIN(size, sizeof(buffer) - 1));
	fprintf(fp, fmt, buffer);
}

static WINPR_NORETURN(void usage(const char* app, const char* invalid))
{
	FILE* fp = stdout;

	fprintf(fp, "Invalid argument '%s'\n", invalid);
	fprintf(fp, "Usage: %s <arg>[ <arg> ...]\n", app);
	fprintf(fp, "Arguments:\n");
	print_entry(fp, "\t%s<cert file>\n", options.scert, sizeof(options.scert));
	print_entry(fp, "\t%s<key file>\n", options.skey, sizeof(options.skey));
	print_entry(fp, "\t%s<port>\n", options.sport, sizeof(options.sport));
	print_entry(fp, "\t%s\n", options.slocal_only, sizeof(options.slocal_only));
	exit(-1);
}

int main(int argc, char* argv[])
{
	int rc = -1;
	BOOL started = FALSE;
	WSADATA wsaData = { 0 };
	freerdp_listener* instance = NULL;
	char* file = NULL;
	char name[MAX_PATH] = { 0 };
	long port = 3389;
	BOOL localOnly = FALSE;
	struct server_info info = { 0 };
	const char* app = argv[0];

	errno = 0;

	for (int i = 1; i < argc; i++)
	{
		char* arg = argv[i];

        if (strncmp(arg, options.sport, sizeof(options.sport)) == 0)
		{
			const char* sport = &arg[sizeof(options.sport)];
			port = strtol(sport, NULL, 10);

			if ((port < 1) || (port > UINT16_MAX) || (errno != 0))
				usage(app, arg);
		}
		else if (strncmp(arg, options.slocal_only, sizeof(options.slocal_only)) == 0)
			localOnly = TRUE;
		else if (strncmp(arg, options.scert, sizeof(options.scert)) == 0)
		{
			info.cert = &arg[sizeof(options.scert)];
			if (!winpr_PathFileExists(info.cert))
				usage(app, arg);
		}
		else if (strncmp(arg, options.skey, sizeof(options.skey)) == 0)
		{
			info.key = &arg[sizeof(options.skey)];
			if (!winpr_PathFileExists(info.key))
				usage(app, arg);
		}
		else
			usage(app, arg);
	}

	//WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi());
	winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT);
	instance = freerdp_listener_new();

	if (!instance)
		return -1;

	if (!info.cert)
		info.cert = "server.crt";
	if (!info.key)
		info.key = "server.key";

	instance->info = (void*)&info;
	instance->PeerAccepted = test_peer_accepted;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		goto fail;

	/* Open the server socket and start listening. */
	sprintf_s(name, sizeof(name), "freerdp-broker.%ld", port);
	file = GetKnownSubPath(KNOWN_PATH_TEMP, name);

	if (!file)
		goto fail;

	if (localOnly)
	{
		WINPR_ASSERT(instance->OpenLocal);
		started = instance->OpenLocal(instance, file);
	}
	else
	{
		WINPR_ASSERT(instance->Open);
		started = instance->Open(instance, NULL, (UINT16)port);
	}

	if (started)
	{
		/* Entering the server main loop. In a real server the listener can be run in its own thread */
		test_server_mainloop(instance);
	}

	rc = 0;
fail:
	free(file);
	freerdp_listener_free(instance);
	WSACleanup();
	return rc;
}
