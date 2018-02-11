#ifndef PARSER_H_INCLUDED
#define PARSER_H_INCLUDED

#include <vector>
#include <string>
#include <fstream>
class Parser {
    private:
        std::vector<int> numbers;
        std::ifstream myFile;
    public:
        Parser();
        ~Parser();
        parseFromFile(std::ifstream);
        parseFromString(std::string);
    };

#endif // PARSER_H_INCLUDED
