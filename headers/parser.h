#ifndef PARSER_H_INCLUDED
#define PARSER_H_INCLUDED

#include <iostream>
#include<fstream>
#include <sstream>
#include <string>
#include <vector>
#include <bitset>
class Parser {
    private:
        std::vector<int> numbers;
        std::ifstream is;
        bool checkSum();
        int IHL;
    public:
        Parser();
        ~Parser();
        void parseFromFile(std::string);
        void parseFromString(std::string);
        void ethernetHeader();
        void ipHeader();
        void printList();
        void tcpHeader();
    };

#endif // PARSER_H_INCLUDED
