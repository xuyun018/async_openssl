#include "XYSocket.h"
#include "ssl_shell.h"

#include <Windows.h>

#pragma comment(lib, "crypt32.lib")
#ifdef _M_X64
#pragma comment(lib, "openssl/libraries64/libcrypto.lib")
#pragma comment(lib, "openssl/libraries64/libssl.lib")
#else
#pragma comment(lib, "openssl/libraries32/libcrypto.lib")
#pragma comment(lib, "openssl/libraries32/libssl.lib")
#endif

struct my_session
{
	struct _ssl_session pss[1];

	unsigned int flags;
};

int CALLBACK SocketProcedure(LPVOID parameter, LPVOID **pointer, LPVOID context, 
	SOCKET s, BYTE type, BYTE number, SOCKADDR *psa, int *salength, const char *buffer, int length)
{
	PXYSOCKET ps = (PXYSOCKET)parameter;
	struct _ssl_shell *pshell = (struct _ssl_shell *)ps->parameter1;
	PXYSOCKET_CONTEXT psc = (PXYSOCKET_CONTEXT)context;
	struct my_session *psession;
	unsigned char *p;
	int result = 0;
	unsigned int l0;
	unsigned int l1;
	unsigned int l;
	unsigned int bufferlength;
	unsigned char address[0x1c04];
	PSOCKADDR_IN psai;
	unsigned char command;

	switch (number)
	{
	case XYSOCKET_CLOSE:
		switch (type)
		{
		case XYSOCKET_TYPE_TCP:
			break;
		case XYSOCKET_TYPE_TCP0:
		case XYSOCKET_TYPE_TCP1:
			psession = (struct my_session *)psc->context;
			_ssl_session_uninitialize((struct _ssl_session *)psession);
			FREE(psession);
			//
			break;
		default:
			break;
		}
		break;
	case XYSOCKET_CONNECT:
		switch (type)
		{
		case XYSOCKET_TYPE_TCP0:
			switch (length)
			{
			case 0:
				// 成功
				if (pointer)
				{
					psession = (struct my_session *)psc->context;
					if (psession)
					{
						psession->flags = 0;

						if (_ssl_session_initialize((struct _ssl_session *)psession, pshell->ctx1, 1))
						{
							_ssl_handshake((struct _ssl_session *)psession, s);
						}
					}
				}
				break;
			case XYSOCKET_ERROR_FAILED:
			case XYSOCKET_ERROR_REFUSED:
			case XYSOCKET_ERROR_OVERFLOW:
			default:
				break;
			}
			break;
		case XYSOCKET_TYPE_TCP1:
			switch (length)
			{
			case XYSOCKET_ERROR_ACCEPT:
				psai = (PSOCKADDR_IN)psa;

				psai->sin_family = AF_INET;

				*salength = sizeof(SOCKADDR_IN);
				break;
			case XYSOCKET_ERROR_ACCEPTED:
				OutputDebugString(L"Server accept ok\r\n");
				{
					if (psession = (struct my_session *)MALLOC(sizeof(struct my_session)))
					{
						psession->flags = 0;

						if (_ssl_session_initialize((struct _ssl_session *)psession, pshell->ctx0, 0))
						{
						}

						psc->context = psession;
					}
				}
				break;
			case XYSOCKET_ERROR_OVERFLOW:
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
		break;
	case XYSOCKET_RECV:
		switch (type)
		{
		case XYSOCKET_TYPE_TCP0:
			// 这里是 client 的 socket
		case XYSOCKET_TYPE_TCP1:
			// 这里是 server 的 socket
			if (pointer == NULL)
			{
				psession = (struct my_session *)psc->context;

				int err_code = 0;
				int connected;
				int flag = 1;

				int rv = _ssl_read((struct _ssl_session *)psession, s,
					buffer, length, &err_code, &connected);
				if (connected || (psession->flags & 1))
				{
					//psession->flags |= 1;

					if (type == XYSOCKET_TYPE_TCP0)
					{
						const char* request = "GET / HTTP/1.1\r\n"
							"Connection: keep-alive\r\n"
							"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)\r\n"
							"Host: %s:%d\r\n"
							"Pragma: no-cache\r\n"
							"Content-Type: application/octet-stream\r\n"
							"Accept-Encoding: deflate, gzip\r\n\r\n";

						char reqbuf[1024];
						wsprintfA(reqbuf, request, "www.baidu.com", 443);

						_ssl_write((struct _ssl_session *)psession, s,
							(const void *)reqbuf, strlen(reqbuf));
					}
					else
					{
						const char* response = "HTTP/1.1 200 OK\r\n"
							"Connection: keep-alive\r\n"
							"Pragma: no-cache\r\n"
							"Content-Type: application/octet-stream\r\n"
							"Accept-Encoding: deflate, gzip\r\n\r\n";

						char reqbuf[1024];
						wsprintfA(reqbuf, response, "www.baidu.com", 443);

						_ssl_write((struct _ssl_session *)psession, s,
							(const void *)reqbuf, strlen(reqbuf));
					}
				}
				rv = err_code;
				if (rv > 0)
				{
					char tbuf[8196];
					memcpy(tbuf, buffer, rv);
					tbuf[rv] = '\0';
					printf("%s\r\n", tbuf);
				}
			}
			break;
		default:
			break;
		}
		break;
	case XYSOCKET_SEND:
		break;
	case XYSOCKET_TIMEOUT:
		switch (type)
		{
		case XYSOCKET_TYPE_TCP:
			//OutputDebugString(_T("listener timeout\r\n"));
			break;
		case XYSOCKET_TYPE_TCP0:
			break;
		case XYSOCKET_TYPE_TCP1:
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return(result);
}

int wmain(int argc, WCHAR *argv[])
{
	XYSOCKET ps[1];
	struct _ssl_shell pshell[1];
	struct my_session *psession;
	SOCKET fd;

	if (argc > 1)
	{
		WSADATA wsad;

		WSAStartup(MAKEWORD(2, 2), &wsad);

		_ssl_initialize(pshell);

		XYSocketsStartup(ps, NULL, (LPVOID)pshell, SocketProcedure);

		unsigned int i;
		unsigned int j;
		char str[256];
		char ch;

		i = 0;
		j = 0;
		while (ch = str[i] = argv[1][i])
		{
			if (ch >= '0' && ch <= '9')
			{
			}
			else
			{
				//break;
			}

			if (ch == ':')
			{
				j = i + 1;
			}

			i++;
		}

		struct sockaddr_in sai;

		sai.sin_family = AF_INET;

		fd = -1;

		if (j)
		{
			XYSocketLaunchThread(ps, XYSOCKET_THREAD_CONNECT, 64);
			XYSocketLaunchThread(ps, XYSOCKET_THREAD_CLIENT, 64);

			str[j - 1] = '\0';
			sai.sin_addr.S_un.S_addr = inet_addr(str);
			sai.sin_port = htons(atoi(str + j));

			if (psession = (struct my_session *)MALLOC(sizeof(struct my_session)))
			{
				fd = XYTCPConnect(ps, (void *)psession, (const struct sockaddr*)&sai, sizeof(sai), 0);
			}
		}
		else
		{
			XYSocketLaunchThread(ps, XYSOCKET_THREAD_LISTEN, 64);
			XYSocketLaunchThread(ps, XYSOCKET_THREAD_SERVER, 1024);

			const char *pcrt_file = "server-cert.pem";
			const char *pkey_file = "server-key.pem";
			char crt_file[128];
			char key_file[128];

			if (argc > 3)
			{
				i = 0;
				while (crt_file[i] = argv[2][i])
				{
					i++;
				}
				i = 0;
				while (key_file[i] = argv[3][i])
				{
					i++;
				}

				pcrt_file = crt_file;
				pkey_file = key_file;
			}

			_ssl_inhale(pshell->ctx0,
				pcrt_file, pkey_file, "ALL:!EXPORT:!LOW");

			sai.sin_port = htons(atoi(str));
			sai.sin_addr.s_addr = htonl(INADDR_ANY);

			fd = XYTCPListen(ps, NULL, NULL, (const SOCKADDR *)&sai, sizeof(sai));
		}

		getchar();

		XYSocketsCleanup(ps);

		_ssl_uninitialize(pshell);

		WSACleanup();
	}

	return(0);
}
