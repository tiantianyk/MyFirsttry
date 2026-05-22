#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <windows.h>

using namespace std;

using std::uint64_t;

// 闰秒记录：{GPS秒数累计, 闰秒偏移量}
struct LeapSecond {
    uint64_t gps_seconds;  // 该闰秒生效时的GPS秒数（自GPS纪元起）
    int      offset;       // 此时起GPS领先UTC的秒数
};

// GPS纪元：1980-01-06 00:00:00 UTC
// GPS时间 = UTC时间 + 闰秒偏移
const vector<LeapSecond> LEAP_SECONDS = {
    // 日期            GPS秒          偏移
    {  47347200,  1 },  // 1981-07-01
    {  78926400,  2 },  // 1982-07-01
    { 110448000,  3 },  // 1983-07-01
    { 173491200,  4 },  // 1985-07-01
    { 252028800,  5 },  // 1988-01-01
    { 315187200,  6 },  // 1990-01-01
    { 346723200,  7 },  // 1991-01-01
    { 393984000,  8 },  // 1992-07-01
    { 425520000,  9 },  // 1993-07-01
    { 457056000, 10 },  // 1994-07-01
    { 504489600, 11 },  // 1996-01-01
    { 551750400, 12 },  // 1997-07-01
    { 599184000, 13 },  // 1999-01-01
    { 820108800, 14 },  // 2006-01-01
    { 914803200, 15 },  // 2009-01-01
    { 1025136000, 16 }, // 2012-07-01
    { 1119744000, 17 }, // 2015-07-01
    { 1167264000, 18 }, // 2017-01-01
};

// 根据GPS秒数获取当前的闰秒偏移
int get_leap_offset(uint64_t gps_seconds) {
    int offset = 0;
    for (const auto& ls : LEAP_SECONDS) {
        if (gps_seconds >= ls.gps_seconds) {
            offset = ls.offset;
        } else {
            break;
        }
    }
    return offset;
}

// 判断闰年
bool is_leap(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

// 每月的天数
int days_in_month(int year, int month) {
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month == 2 && is_leap(year)) return 29;
    return days[month - 1];
}

// GPS秒数 → UTC年月日 + TOD（含闰秒修正）
struct UTCTime {
    int year, month, day;
    int hour, minute, second;
};

UTCTime gps_to_utc(uint64_t gps_seconds) {
    // 闰秒偏移
    int leap = get_leap_offset(gps_seconds);

    // GPS = UTC + leap → UTC秒 = GPS秒 - leap
    uint64_t utc_seconds = gps_seconds - leap;

    // 从GPS纪元 1980-01-06 开始推算日期
    // 先算出从1970-01-01的秒数，再用标准方法换算
    // GPS纪元 = 1980-01-06 = 1970-01-01 + 315964800秒（含GPS纪元时的10个闰秒）
    // 简化处理：从1980-01-06逐日推算
    int year = 1980;
    int month = 1;
    int day = 6;

    uint64_t remaining = utc_seconds;

    // 跳过1980年的剩余天数
    int days_left_1980 = 0;
    for (int m = 1; m <= 12; m++) {
        days_left_1980 += days_in_month(1980, m);
    }
    days_left_1980 -= 5; // 减去1月1日到1月5日

    uint64_t sec_per_day = 86400;
    uint64_t days = remaining / sec_per_day;
    uint64_t sec_of_day = remaining % sec_per_day;

    // 从1980-01-06开始加天数
    year = 1980;
    month = 1;
    day = 6;

    while (days >= 366 + (is_leap(year) ? 1 : 0)) {
        int days_this_year = is_leap(year) ? 366 : 365;
        if (days >= (uint64_t)days_this_year) {
            days -= days_this_year;
            year++;
        } else {
            break;
        }
    }

    while (true) {
        int dim = days_in_month(year, month);
        if (days >= (uint64_t)dim) {
            days -= dim;
            month++;
            if (month > 12) {
                month = 1;
                year++;
            }
        } else {
            day += (int)days;
            break;
        }
    }

    // 处理day溢出
    while (day > days_in_month(year, month)) {
        day -= days_in_month(year, month);
        month++;
        if (month > 12) {
            month = 1;
            year++;
        }
    }

    int hour = (int)(sec_of_day / 3600);
    int minute = (int)((sec_of_day % 3600) / 60);
    int second = (int)(sec_of_day % 60);

    return {year, month, day, hour, minute, second};
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    cout << "=== GPS时间 → UTC TOD 转换器 ===" << endl;
    cout << "（已考虑闰秒，当前偏移: GPS领先UTC " << LEAP_SECONDS.back().offset << "秒）" << endl << endl;

    // 示例1：GPS纪元起点
    cout << "--- 示例1: GPS纪元起点 ---" << endl;
    cout << "GPS秒数: 0 (1980-01-06 00:00:00 GPS)" << endl;
    auto t1 = gps_to_utc(0);
    cout << "UTC时间: " << t1.year << "-"
         << setw(2) << setfill('0') << t1.month << "-"
         << setw(2) << setfill('0') << t1.day << " "
         << setw(2) << setfill('0') << t1.hour << ":"
         << setw(2) << setfill('0') << t1.minute << ":"
         << setw(2) << setfill('0') << t1.second
         << " (UTC)" << endl;
    cout << "TOD: " << setw(2) << setfill('0') << t1.hour << ":"
         << setw(2) << setfill('0') << t1.minute << ":"
         << setw(2) << setfill('0') << t1.second << endl << endl;

    // 示例2：2024-01-01 00:00:00 UTC (GPS秒约 1388011246)
    cout << "--- 示例2: 当前时间示例 ---" << endl;
    uint64_t gps_now = 1388534400; // 2024-01-06 00:00:00 GPS
    cout << "GPS秒数: " << gps_now << endl;
    auto t2 = gps_to_utc(gps_now);
    cout << "UTC时间: " << t2.year << "-"
         << setw(2) << setfill('0') << t2.month << "-"
         << setw(2) << setfill('0') << t2.day << " "
         << setw(2) << setfill('0') << t2.hour << ":"
         << setw(2) << setfill('0') << t2.minute << ":"
         << setw(2) << setfill('0') << t2.second
         << " (UTC)" << endl;
    cout << "TOD: " << setw(2) << setfill('0') << t2.hour << ":"
         << setw(2) << setfill('0') << t2.minute << ":"
         << setw(2) << setfill('0') << t2.second << endl << endl;

    // 示例3：GPS周 + 周内秒 格式输入
    cout << "--- 示例3: GPS周+周内秒 格式 ---" << endl;
    int gps_week = 2300;
    uint64_t sow = 345600; // 周内秒
    uint64_t total_gps_sec = (uint64_t)gps_week * 604800 + sow;
    cout << "GPS周: " << gps_week << ", 周内秒: " << sow
         << " → 总GPS秒: " << total_gps_sec << endl;
    auto t3 = gps_to_utc(total_gps_sec);
    cout << "UTC时间: " << t3.year << "-"
         << setw(2) << setfill('0') << t3.month << "-"
         << setw(2) << setfill('0') << t3.day << " "
         << setw(2) << setfill('0') << t3.hour << ":"
         << setw(2) << setfill('0') << t3.minute << ":"
         << setw(2) << setfill('0') << t3.second
         << " (UTC)" << endl;
    cout << "TOD: " << setw(2) << setfill('0') << t3.hour << ":"
         << setw(2) << setfill('0') << t3.minute << ":"
         << setw(2) << setfill('0') << t3.second << endl << endl;

    // 交互输入
    cout << "=== 手动输入GPS秒数 ===" << endl;
    cout << "请输入GPS秒数（自1980-01-06 00:00:00起）: ";
    uint64_t user_sec;
    if (cin >> user_sec) {
        auto t = gps_to_utc(user_sec);
        cout << "当前闰秒偏移: GPS领先UTC " << get_leap_offset(user_sec) << "秒" << endl;
        cout << "UTC时间: " << t.year << "-"
             << setw(2) << setfill('0') << t.month << "-"
             << setw(2) << setfill('0') << t.day << " "
             << setw(2) << setfill('0') << t.hour << ":"
             << setw(2) << setfill('0') << t.minute << ":"
             << setw(2) << setfill('0') << t.second
             << " (UTC)" << endl;
        cout << "TOD: "
             << setw(2) << setfill('0') << t.hour << ":"
             << setw(2) << setfill('0') << t.minute << ":"
             << setw(2) << setfill('0') << t.second << endl;
    }

    return 0;
}
