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
    is.close();
    }

void Parser::printList() {
    std::cout <<"n: " <<numbers.size()<<"\n";
    for(auto&& number: numbers) {
        std::cout<<std::hex <<number<<" ";
        }
    std::cout <<"\n\n\n";
    }

void Parser::ethernetHeader() {
    std::cout <<"Mac de destino: "<<std::hex;
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
    //se asigna la posición 14 a la variable a
    int a = numbers[14];
    //se asigna los últimos 4 bits de "a" a la variable b
    int b = a>>4 &0xf;
    //se asignan los primeros 4 bits de "a" la variable c
    int c = a&0xf;

    std::cout<<"\n\nVersion de ip: "<<b<<"\n";
    //el valor se imprime en decimal
    std::cout<<"\nIHL = "<<std::dec<<b*c<<"\n";
    //se regresa el standar output a hexadecimal
    std::cout<<std::hex;
    //se asigna el valor 15 del vector a a
    a = numbers[15];
    //se crea un bitset a partir de esa variable
    std::bitset<8> m(a);
    //se crea un bitset de 3 bits para el presedente
    std::bitset<3>t;
    //se asignan los primeros (primero el más significativo) 3 bits de m a t
    t[2]=m[7];
    t[1]=m[6];
    t[0]=m[5];
    //se crea un bitset de 4 bits para el TOS
    std::bitset<4> s;
    //se asignan los bits 4 a 1 de m a s
    s[3]=m[4];
    s[2]=m[3];
    s[1]=m[2];
    s[0]=m[1];
    //casting del bitset t para evaluar posibilidades
    int rs = (int)(t.to_ulong());
    std::cout <<"\nPrecedente: ";
    switch(rs){
        case 0b000:
            std::cout <<"Rutina\n";
            break;
        case 0b001:
            std::cout <<"Prioridad\n";
            break;
        case 0b010:
            std::cout<<"Inmediato\n";
            break;
        case 0b011:
            std::cout <<"Flash\n";
            break;
        case 0b100:
            std::cout <<"Flash Override\n";
            break;
        case 0b101:
            std::cout <<"Critico\n";
            break;
        case 0b110:
            std::cout <<"Control de red\n";
            break;
        case 0b111:
            std::cout <<"Control inter red\n";
            break;
        }
        rs=(int)(s.to_ulong());
        std::cout<<"\nTOS: ";
        switch(rs){
            case 0b0000:
                std::cout<<"Normal\n";
                break;
            case 0b0001:
                std::cout<<"Minimizar coste\n";
                break;
            case 0b0010:
                std::cout<<"Maximizar fiabilidad\n";
                break;
            case 0b0100:
                std::cout<<"Maximizar densidad de flujo\n";
                break;
            case 0b1000:
                std::cout<<"Maximizar recorrido\n";
                break;
            default:
                std::cout<<"No asignado";
            }
    //TAMAÑO DE DATAGRAMA
    int mm;
    mm=(numbers[16]<<8|numbers[17]);
    std::cout<<std::dec<<"Tamaño del datagrama: "<<mm<<" bytes\n";
    //ID DEL DATAGRAMA
    mm=(numbers[18]<<8|numbers[19]);
    std::cout<<"\nId del datagrama: "<<mm<<"\n";

    //FLAG1 MF & DF
    std::bitset<8>pf(numbers[20]);
    std::bitset<3>flags;
    flags[2]=pf[7];
    flags[1]=pf[6];
    flags[0]=pf[5];
    std::cout<<"\nBandera 1: "<<flags[0]<<"\n";
    std::cout<<"\nDF: ";
    if(flags[1]){
        std::cout<<"True\n";
        }
    else{
        std::cout<<"False\n";
        }
    std::cout<<"\nMF: ";
    if((bool)flags[2]){
        std::cout<<"True\n";
        }
    else{
        std::cout<<"False\n";
        }

    //DESFACE DEL DATAGRAMA
    int fOffset;
    fOffset =((numbers[20]<<16)|numbers[21])&0x1FFF;
    std::bitset<16>tem(fOffset);
    std::cout<<std::dec<<"\nDesface del datagrama: "<<fOffset<<"\n";

    //TIEMPO DE VIDA
    std::cout<<"\nTIempo de vida: "<<numbers[22]<<" saltos\n";
    //PROTOCOLO
    std::cout<<"\nTipo de protocolo: ";
    switch(numbers[23]){
        case 0x00:
            std::cout<<"HOPOPT\n";
            break;
        case 0x01:
            std::cout<<"ICMP\n";
            break;
        case 0x02:
            std::cout<<"IGMP\n";
            break;
        case 0x03:
            std::cout<<"GGP\n";
            break;
        case 0x04:
            std::cout<<"IP-in-IP\n";
            break;
        case 0x05:
            std::cout<<"ST\n";
            break;
        case 0x06:
            std::cout<<"TCP\n";
            break;
        default:
            std::cout<<"En desarrollo\n";
        }

        //CRC16
        int crc;
        crc= (numbers[24]<<8)|numbers[25];
        std::cout<<"\nChecksum: "<<std::hex<<crc<<"\n";

        //IP de origen

        std::cout<<std::dec<<"\nIp de origen: ";
        for(std::vector<int>::iterator it = numbers.begin()+26; it!=numbers.begin()+30; it++) {
        std::cout << *it;
        if(it!=numbers.begin()+29) {
            std::cout<<".";
            }
        }
        std::cout<<std::dec<<"\n\nIp de destino: ";
        for(std::vector<int>::iterator it = numbers.begin()+30; it!=numbers.begin()+34; it++) {
        std::cout << *it;
        if(it!=numbers.begin()+33) {
            std::cout<<".";
            }
        }
    }
