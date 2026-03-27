#pragma once

#include <iostream>
#include <string>
#include <mutex>

/**
 * @enum LogLevel
 * @brief Severity levels for logging.
 */
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    NONE = 4
};

/**
 * @class Logger
 * @brief Simple thread-safe logger for heiFIP.
 */
class Logger {
public:
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    void setLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(mutex_);
        currentLevel_ = level;
    }

    LogLevel getLevel() const {
        return currentLevel_;
    }

    void log(LogLevel level, const std::string& message) {
        if (level < currentLevel_) return;

        std::lock_guard<std::mutex> lock(mutex_);
        std::ostream& os = (level >= LogLevel::WARNING) ? std::cerr : std::cout;

        os << "[" << levelToString(level) << "] " << message << std::endl;
    }

private:
    Logger() : currentLevel_(LogLevel::INFO) {}
    ~Logger() = default;

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::string levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG:   return "DEBUG";
            case LogLevel::INFO:    return "INFO";
            case LogLevel::WARNING: return "WARNING";
            case LogLevel::ERROR:   return "ERROR";
            default:                return "UNKNOWN";
        }
    }

    LogLevel currentLevel_;
    std::mutex mutex_;
};

// Convenience macros for logging
#define LOG_DEBUG(msg) Logger::getInstance().log(LogLevel::DEBUG, msg)
#define LOG_INFO(msg)  Logger::getInstance().log(LogLevel::INFO, msg)
#define LOG_WARN(msg)  Logger::getInstance().log(LogLevel::WARNING, msg)
#define LOG_ERROR(msg) Logger::getInstance().log(LogLevel::ERROR, msg)

// Helper for stream-style logging (optional but nice)
#include <sstream>
#define LOG_STREAM(level, msg) { \
    if (level >= Logger::getInstance().getLevel()) { \
        std::stringstream ss; \
        ss << msg; \
        Logger::getInstance().log(level, ss.str()); \
    } \
}

#define LDEBUG(msg) LOG_STREAM(LogLevel::DEBUG, msg)
#define LINFO(msg)  LOG_STREAM(LogLevel::INFO, msg)
#define LWARN(msg)  LOG_STREAM(LogLevel::WARNING, msg)
#define LERROR(msg) LOG_STREAM(LogLevel::ERROR, msg)
