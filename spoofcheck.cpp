// Reza Naeemi


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>


using namespace std;

const static int NUMBER_OF_CONNECTIONS = 5;
const static int START_OF_VALID_PORT_NUMBER_RANGE = 1024;
const static int END_OF_VALID_PORT_NUMBER_RANGE = 65536;



void displayUsage()
{
	cerr << "usage: ./spoofcheck port" << endl;
}


bool isInvalidPortNumber(const int portNumber)
{
	return (
          (portNumber < START_OF_VALID_PORT_NUMBER_RANGE) || 
          (portNumber > END_OF_VALID_PORT_NUMBER_RANGE));
}

int main(int argc, char* argv[])
{
	// Check arguments count, to ensure there are exactly 2.
	if (argc != 2)
	{
		displayUsage();

		return -1;
	}

	
	if (isInvalidPortNumber(atoi(argv[1])))
	{
		cerr << "Cannot bind the local address to the server socket." << endl;

		return -1;
	}

	// 1. Use argv[1] in argument as the port to which spoofcheck.cpp should bind itself.
	int serverPortNumber = atoi(argv[1]);


	// Construct the receiving socket address for any server interface that is available.
	sockaddr_in acceptSocketAddress;
	bzero((char*)&acceptSocketAddress, sizeof(acceptSocketAddress));
	acceptSocketAddress.sin_family = AF_INET;					// Address Family: Internet
	acceptSocketAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	acceptSocketAddress.sin_port = htons(serverPortNumber);

  // 2. Instantiate a TCP socket.
	int serverSD = socket(AF_INET, SOCK_STREAM, 0);
	
	const int ON = 1;

	setsockopt(serverSD, SOL_SOCKET, SO_REUSEADDR, (char*)&ON, sizeof(acceptSocketAddress));
	
	
	// Bind the TCP socket
	int returnCode = bind(serverSD, (sockaddr*)&acceptSocketAddress, sizeof(acceptSocketAddress));
	
	if (returnCode < 0)	// A negative returnCode means that the bind failed.
	{
    cerr << "Bind failed." << endl;
    
    close(serverSD);
    
    return -1;  
	}
 
  // Listen for a connection
  listen(serverSD, NUMBER_OF_CONNECTIONS);    // Set the number of pending connections
  
  // 3. Go into an infinite loop (while (true) ...) where:
  while (true)
  {
    // Wait for a client to connect
    sockaddr_in clientSocketAddress;
    socklen_t clientSocketAddressSize = sizeof(clientSocketAddress);
    
    // 1. Accept a new connection from a client through accept().
    int newSD = accept(serverSD, (sockaddr*)&clientSocketAddress, &clientSocketAddressSize);
    
    
    // 2. Spawn a child process through fork(). The parent closes this connection and goes back to the top of the loop, 
    // whereas the child continues checking the integrity of this connection.
    // Create a new copy process thread for every new connection
    // (Multithreading)
    if (fork() == 0)
    { 
      close(serverSD);
      
      // 3. Retrieve the client's IP address and port of this connection through getpeername().
      // Get this client's IP address and port number using the getpeername() function.
      getpeername(newSD, (sockaddr*)&clientSocketAddress, &clientSocketAddressSize);
      
      
      // Get the client IP address and Port Number in a readable format
      char* clientIPAddress = inet_ntoa(clientSocketAddress.sin_addr);
      int clientPortNumber = ntohs(clientSocketAddress.sin_port);
      
      cout << "client addr = " << clientIPAddress << 
              " port = " << clientPortNumber << endl;
      
      
      // Get the client's hostent data structure using gethostbyaddr().
      int unsigned clientsHostentDataStructure = inet_addr(clientIPAddress);
      
      // 5. Retrieve the client's official name, aliases, and registered IP addresses from the hostent.
      struct hostent* hostentPtr = gethostbyaddr((const void*)&clientsHostentDataStructure, sizeof(unsigned int), AF_INET);
      
      
      // 6. Decide whether this client is a honest or a spoofing client by matching its IP address retrieved from getpeername()
      // and the list of addresses retrieved via gethostbyaddr(). (In other words, if you confirm that the client's IP address 
      // of this connection matches one of the addresses listed in hostent, you can trust this client.)
      if (hostentPtr == NULL)
      {
        cout << "gethostbyaddr error for the client( " << clientIPAddress << "): 1" << endl;
        cout << "a spoofing client" << endl;
        cout << endl;
      }
      else
      {
        // Get the client's official name, all aliases, 
        // and the IP addresses that are registered using the hostent.
        char* clientHostName = hostentPtr->h_name;
        
        cout << "official hostname: " << clientHostName << endl;
        
        // Report all aliases, if connetion under alias.
        int aliasCount = 0;
        
        for (char** alias = hostentPtr->h_aliases; *alias != NULL; alias++)
        {
          cout << "alias: " << *alias << endl;
          
          aliasCount++;
        }
        
        
        if (aliasCount == 0)
        {
          cout << "alias: none" << endl;
        }
        
        
        // Verify the client is legit by confirming the IP Address(es) that we got
        // from getpeername() and the list of addresses that we get from
        // the gethostbyaddr(). Basically, if we can confirm that the client's IP
        // address of this connection matches one of the addresses that is listed
        // in the hostent, then we can trust the client.
        bool isHonestClient = false;
        
        switch(hostentPtr->h_addrtype)
        {
          case AF_INET:
            in_addr* addressList;
            int addressListSize;
            char* registeredIPAddress;
            
            // Get all client IP addresses bound.  For each, display the address.
            for (addressListSize = 0; (addressList = (in_addr*)hostentPtr->h_addr_list[addressListSize]) != NULL; addressListSize++)
            {
              registeredIPAddress = inet_ntoa(*addressList);
              cout << "ip address: " << registeredIPAddress << " ... hit! " << endl;
            }
                        
            // Match the advertised IP address with addresses bound to the client.
            // If a match is found, report the client as legit.
            for (int i = 0; i <= addressListSize; i++)
            {
              if (clientIPAddress == registeredIPAddress)
              {
                isHonestClient = true;
                
                break;    // Break out of the loop, once client is considered honest.
              }
            }
                        
            if (isHonestClient)
            {
              cout << "an honest client" << endl;
            }
            else
            {
              cout << "a spoofing client" << endl;
            }
            
            cout << endl;
                        
            break;
            
            default:
              cerr << "Unknown address type." << endl;
              break;
            }
          }
          
          // 7. Terminate this child process. 
          close(newSD);
          exit(0);
             
        }
        else
        {
          close(newSD);
        }
    }
    
    close(serverSD);    
    return 0;          
}
        
