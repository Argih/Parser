#include "headers/parser.h"

Parser::Parser() {

    }

Parser::~Parser() {

    }

void Parser::parseFromFile( std::string myString) {
    is.open(myString);

    std::string number_as_string;
    while (std::getline(is, number_as_string, ' ')) {
        std::stringstream ss;
        ss<<std::hex<<number_as_string;

        int lol;
        ss>>lol;
        numbers.push_back((int)lol);
        }
    }

void Parser::printList() {
    std::cout <<"n: " <<numbers.size()<<"\n";
    for(auto&& number: numbers) {
        std::cout<<std::hex <<number<<" ";
        }
    std::cout <<"\n\n\n";
    }

void Parser::ethernetHeader() {
    std::cout <<"Mac de destino: ";
    for(std::vector<int>::iterator it = numbers.begin(); it!=numbers.begin()+6; it++) {
        std::cout << *it;
        if(it!=numbers.begin()+5) {
            std::cout<<":";
            }
        }
    std::cout<<"\n\nMac de origen: ";
    for(std::vector<int>::iterator it = numbers.begin()+6; it!=numbers.begin()+12; it++) {
        std::cout << *it;
        if(it!=numbers.begin()+11) {
            std::cout<<":";
            }
        }

    int a = (numbers[12]<<8) | (numbers[13]);
    if(a>0x5DC){
    std::cout<<"\n\nTipo de trama: ";
    switch(a){
        case 0x0800:
            std::cout<< "Ip v4";
            break;
        case 0x0806:
            std::cout<<"ARP";
                break;
        default :
            std::cout<<"Desconocido";
            }
        }
    else{
         std::cout<<"Tamaño de trama: "<<std::dec<<a<<"bytes";
        }
    }

void Parser::ipHeader() {
    }
