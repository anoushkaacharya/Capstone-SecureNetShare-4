#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <chrono>
#include <ctime>
#include <iostream>

inline std::string current_time() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::string s = std::ctime(&t);
    s.pop_back();
    return s;
}

inline void log_event(const std::string &msg) {
    std::cout << "[" << current_time() << "] " << msg << std::endl;
}

#endif