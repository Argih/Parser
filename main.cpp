#include <iostream>
#include "headers/parser.h"
using namespace std;

int main()
{
string my="trama.txt";
Parser myParser;

myParser.parseFromFile(my);
//myParser.printList();
myParser.ethernetHeader();
myParser.ipHeader();
myParser.tcpHeader();
}
