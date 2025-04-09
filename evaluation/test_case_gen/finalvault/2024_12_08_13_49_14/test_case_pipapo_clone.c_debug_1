#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <nftnl/nftnl.h>  
#include <nftnl/rule.h>  
#include <nftnl/table.h>  
#include <nftnl/chain.h>  
#include <nftnl/expr.h>  

int main() {  
    struct nftnl_table *table;  
    struct nftnl_chain *chain;  
    struct nftnl_rule *rule;  
    int fd;  

    // 创建 nft 表  
    table = nftnl_table_alloc();  
    nftnl_table_set_family(table, NFPROTO_IPV4);  
    nftnl_table_set_name(table, "test_table");  

    fd = open("/proc/net/netfilter/nf_tables", O_RDWR);  
    if (fd < 0) {  
        perror("Failed to open nf_tables");  
        return 1;  
    }  

    // 添加表  
    if (nftnl_table_write(table, fd) < 0) {  
        perror("Failed to add table");  
        return 1;  
    }  

    // 创建链  
    chain = nftnl_chain_alloc();  
    nftnl_chain_set_table(chain, table);  
    nftnl_chain_set_name(chain, "test_chain");  
    if (nftnl_chain_write(chain, fd) < 0) {  
        perror("Failed to add chain");  
        return 1;  
    }  

    // 创建规则  
    rule = nftnl_rule_alloc();  
    nftnl_rule_set_chain(rule, chain);  
    nftnl_rule_set_expr(rule, NULL);  // 可根据需要设置表达式  
    if (nftnl_rule_write(rule, fd) < 0) {  
        perror("Failed to add rule");  
        return 1;  
    }  

    // 删除规则  
    if (nftnl_rule_delete(rule, fd) < 0) {  
        perror("Failed to delete rule");  
        return 1;  
    }  

    close(fd);  
    nftnl_rule_free(rule);  
    nftnl_chain_free(chain);  
    nftnl_table_free(table);  

    return 0;  
}