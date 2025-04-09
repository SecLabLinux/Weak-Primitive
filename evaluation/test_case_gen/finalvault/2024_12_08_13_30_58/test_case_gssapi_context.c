#include <gssapi/gssapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>  // 添加头文件

int main() {
    OM_uint32 major_status, minor_status;
    gss_name_t target_name = GSS_C_NO_NAME;  // 使用 GSS_C_NO_NAME 表示空名称
    gss_cred_id_t credentials = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_buffer_desc input_name_buffer;

    // 设置目标名称（例如 Kerberos principal）
    input_name_buffer.value = "user@REALM";
    input_name_buffer.length = strlen(input_name_buffer.value);

    // 将字符串转换为 GSSAPI 名称，使用适当的名称类型
    major_status = gss_import_name(&minor_status, &input_name_buffer, 
                                   GSS_C_NT_USER_NAME, &target_name);
    if (major_status != GSS_S_COMPLETE) {
        printf("gss_import_name failed\n");
        return 1;
    }

    // 请求凭证，修正参数类型
    major_status = gss_acquire_cred(&minor_status, target_name, 0, 
                                    GSS_C_NO_OID_SET, GSS_C_ACCEPT, 
                                    &credentials, NULL, NULL, NULL);
    if (major_status != GSS_S_COMPLETE) {
        printf("gss_acquire_cred failed\n");
        return 1;
    }

    // 创建 GSSAPI 上下文，补充第13个参数
    major_status = gss_init_sec_context(&minor_status, credentials, 
                                        &context, target_name, 
                                        GSS_C_NO_OID, 0, 0, 
                                        NULL, NULL, NULL, NULL, NULL, NULL);
    if (major_status != GSS_S_COMPLETE) {
        printf("gss_init_sec_context failed\n");
        return 1;
    }

    printf("GSSAPI context created successfully\n");

    // 清理资源，使用正确的释放函数
    gss_release_cred(&minor_status, &credentials);      // 使用 gss_release_cred
    gss_release_name(&minor_status, &target_name);      // 使用 gss_release_name
    gss_delete_sec_context(&minor_status, &context, NULL);

    return 0;
}