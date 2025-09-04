#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <map>

// 基础操作函数
void vulnerable_operation(const char* data) {
    char buffer[100];
    strcpy(buffer, data);  // 易受攻击的操作
    std::cout << "Vulnerable: " << buffer << std::endl;
}

void safe_operation(const char* data) {
    char buffer[100];
    strncpy(buffer, data, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    std::cout << "Safe: " << buffer << std::endl;
}

// 污点数据管理类
class TaintedData {
private:
    char* data;
    bool is_tainted;
    
public:
    TaintedData(const char* input) : is_tainted(true) {
        data = new char[strlen(input) + 1];
        strcpy(data, input);
    }
    
    ~TaintedData() {
        delete[] data;
    }
    
    void process(bool sanitize = false) {
        if (sanitize) {
            // 数据净化
            char* sanitized = new char[strlen(data) + 1];
            int pos = 0;
            for (int i = 0; data[i]; i++) {
                if (isalnum(data[i])) {
                    sanitized[pos++] = data[i];
                }
            }
            sanitized[pos] = '\0';
            delete[] data;
            data = sanitized;
            is_tainted = false;
            safe_operation(data);
        } else {
            vulnerable_operation(data);
        }
    }

    const char* get_data() const { return data; }
    bool is_clean() const { return !is_tainted; }
};

// 污点传播示例
void demonstrate_taint_propagation(const char* input) {
    // 1. 直接传播
    TaintedData tainted(input);
    tainted.process();  // 未净化
    tainted.process(true);  // 净化后
    
    // 2. 通过容器传播
    std::map<std::string, std::string> data_map;
    data_map["user_input"] = input;
    vulnerable_operation(data_map["user_input"].c_str());
    
    // 3. 通过向量传播
    std::vector<char> vec(input, input + strlen(input));
    char* array = new char[vec.size() + 1];
    std::copy(vec.begin(), vec.end(), array);
    array[vec.size()] = '\0';
    
    vulnerable_operation(array);
    delete[] array;
}

int main() {
    char user_input[200];
    std::cout << "Enter input: ";
    std::cin.getline(user_input, sizeof(user_input));
    
    std::cout << "\n=== Taint Analysis Demo ===" << std::endl;
    demonstrate_taint_propagation(user_input);
    
    return 0;
}
