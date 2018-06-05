/*
* How to read a packet capture file.
*/

/*
* Step 1 - Add includes
*/
#include <string>
#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>

#include <arpa/inet.h>
#include <string.h>
#include <sstream>
#include <fstream>
#include <ctime>
#include <iomanip>

using namespace std;

int main(int argc, char *argv[])
{
    /*
    * Step 2 - Get a file name
    */

    string file = "/home/sentinel/Рабочий\ стол/ModulePCAP/1kxun.pcap";

    /*
    * Step 3 - Create an char array to hold the error.
    */

    // Note: errbuf in pcap_open functions is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
    //       PCAP_ERRBUF_SIZE is defined as 256.
    // http://www.winpcap.org/docs/docs_40_2/html/group__wpcap__def.html
    char errbuff[PCAP_ERRBUF_SIZE];

    /*
    * Step 4 - Open the file and store result in pointer to pcap_t
    */

    // Use pcap_open_offline
    // http://www.winpcap.org/docs/docs_41b5/html/group__wpcapfunc.html#g91078168a13de8848df2b7b83d1f5b69
    pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);

    /*
    * Step 5 - Create a header and a data object
    */

    // Create a header object:
    // http://www.winpcap.org/docs/docs_40_2/html/structpcap__pkthdr.html
    struct pcap_pkthdr *header;

    // }Create a character array using a u_char
    // u_char is defined here:
    // C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Include\WinSock2.h
    // typedef unsigned char   u_char;
    const u_char *data;

    /*
    * Step 6 - Loop through packets and print them to screen
    */
    u_int packetCount = 0;
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        // Print using printf. See printf reference:
        // http://www.cplusplus.com/reference/clibrary/cstdio/printf/

        // Show the packet number
        printf("Packet # %i\n", ++packetCount);

        // Show the size in bytes of the packet
        printf("Packet size: %d bytes\n", header->len);

        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);

        // Show Epoch Time
        printf("Epoch Time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);
        cout << put_time(localtime(&header->ts.tv_sec), "Day %d, Month %b, Year %Y | Time %H:%M:%S") << std::endl;

        // loop through the packet and print it as hexidecimal representations of octets
        // We also have a function that does this similarly below: PrintData()

        cout << endl;
        stringstream mac_to_ss, check_mac_nulls, OUI_ss;
        string mac_addr, check_nulls;
        string find_company[2], mac_company;
        int mac_size = 6;
        int num_mac = 2;
        int cur_pos_mac = 0;
        int OUI = 0;

        for (int i =0; i<num_mac; i++)
        {
        for (cur_pos_mac; cur_pos_mac < mac_size; cur_pos_mac++)
        {
          check_mac_nulls << hex << (int)data[cur_pos_mac];
          check_nulls = check_mac_nulls.str();

          check_mac_nulls.str( std::string() );
          check_mac_nulls.clear();

          int test_first_null = check_nulls.size();
          if (test_first_null == 1)
          {
            mac_to_ss << "0";
            OUI_ss << "0";
          }

          mac_to_ss << hex << (int)data[cur_pos_mac];

          OUI_ss << hex << (int)data[cur_pos_mac];

          if (cur_pos_mac != (mac_size-1))
          {
          mac_to_ss << ":";
          }
          mac_addr = mac_to_ss.str();

          if (cur_pos_mac != (mac_size-4))
          {
          OUI_ss << ":";
          }
          mac_company = OUI_ss.str();

          if (OUI < 3)
          {
            find_company[i] = mac_company;
            OUI++;
          }
          else
          {
            if (cur_pos_mac == mac_size-1)
            {OUI = 0;}
          }

        }
        cout << "MAC " << (i+1) << ": " << mac_addr << endl;
        mac_to_ss.str( std::string() );
        mac_to_ss.clear();
        OUI_ss.str( std::string() );
        OUI_ss.clear();
        mac_size += 6;
        cur_pos_mac = 6;
        }

        cout << "OUI 1" << ": " << find_company[0] << endl;
        cout << "OUI 2" << ": " << find_company[1] << endl;

        ifstream file("/home/sentinel/Рабочий\ стол/ModulePCAP/list_mac_addr_company");

        string s, find;
        char c = '\0';

        while (!file.eof())
        {
        file.get(c);
        s.push_back(c);
        }

        file.close();

        for (int cycle = 0; cycle < 2; cycle++)
        {
        find = find_company[cycle];
        int pos = s.find(find);
        if (pos == -1)
        {
        cout << "Company with this MAC - not finded!" << endl;
        }

        int start_pos = pos+find.length()+1;

        int testing = 0;
        for (int i = start_pos; i < pos+100; i++)
        {
          if (s.at(i) != c)
          {
          testing++;
          }
          else
          {
          break;
          }
        }

        cout << "Company for the " << (cycle+1) << " MAC adress: ";
        for (unsigned i=start_pos; i<pos+find.length()+testing+1; ++i)
        {
          cout << s.at(i);
        }
        cout << endl;
        }

        stringstream user_type_to_ss;
        int match_user = 0;
        string data_from_ss;

        for(int all_pairs = 0; all_pairs < header->caplen; all_pairs++)
        {
          user_type_to_ss << hex << (int)data[all_pairs];
          data_from_ss = user_type_to_ss.str();

          if(data_from_ss == "55")
          {
            user_type_to_ss.str( std::string() );
            user_type_to_ss.clear();
            for (int i = all_pairs+1; i < all_pairs+4; i++)
            {
            user_type_to_ss << hex << (int)data[i];
            data_from_ss += user_type_to_ss.str();
            user_type_to_ss.str( std::string() );
            user_type_to_ss.clear();
            }
            if (data_from_ss == "55736572")
            {
              int end_of_user;
              int incr = all_pairs;
              do
              {
              printf ("%c", data[incr]);
              incr++;
              end_of_user = (int)data[incr];
              } while(end_of_user != 13);
            }
          }

          user_type_to_ss.str( std::string() );
          user_type_to_ss.clear();

          ////////////////////////////////////////////////////////////////////////
          int check_inout;
          check_inout = (int)data[all_pairs-1];
          if(data_from_ss == "53" && check_inout != 77)
          {
            user_type_to_ss.str( std::string() );
            user_type_to_ss.clear();
            for (int i = all_pairs+1; i < all_pairs+6; i++)
            {
            user_type_to_ss << hex << (int)data[i];
            data_from_ss += user_type_to_ss.str();
            user_type_to_ss.str( std::string() );
            user_type_to_ss.clear();
            }
            if (data_from_ss == "536572766572")
            {
              int end_of_server;
              int incr = all_pairs;
              do
              {
              printf ("%c", data[incr]);
              incr++;
              end_of_server = (int)data[incr];
              } while(end_of_server != 13);
            }
          }
          ////////////////////////////////////////////////////////////////////////

          user_type_to_ss.str( std::string() );
          user_type_to_ss.clear();


        }

        cout << endl;
        int next = 0;
        for (u_int i=0; (i < header->caplen ) ; i++)
        {
            // Start printing on the next after every 16 octets
            if ( (i % 16) == 0) printf("\n");
            {
            //if (next > 25 && next < 34)
            if (next < 0)
            {
            // Print each octet as hex (x), make sure there is always two characters (.2).
            printf("%.2x ", data[i]);
            next++;
            }
            else
            {
              printf("%.2x ", data[i]);
            }
            }
        }
        // Add two lines between packets
        printf("\n\n");
    }

    ifstream file1("/home/sentinel/Рабочий\ стол/ModulePCAP/1kxun.pcap");

    string s1, find1;
    char c1 = '\0';

    while (!file1.eof())
    {
    file1.get(c1);
    s1.push_back(c1);
    }

    file1.close();

    find1 = "User-Agent";
    int pos1 = s1.find(find1);
    if (pos1 == -1)
    {
    cout << "Not finded!" << endl;
    }
    else
    {
    cout << "INTERESTINF DATA FOUND!!!!!!!!" << endl;
    }

    }
