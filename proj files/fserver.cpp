//#include <string>
#include <iostream>
//#include <stdio.h>
//#include <fstream>
#include <list>
#include <experimental/filesystem>

namespace fs = std::experimental::filesystem;


int main()
{
    //std::string path = "root";
    //std::list<string> file;
    for (auto & p : fs::recursive_directory_iterator("root")){
        	//char file_path[25];
        	//sprintf(file_path,"%s",p);
        	//file = p.path();
        	std::cout << p << '\n';//std::endl
        }
}

//g++ -o fserv fserver.cpp -lstdc++fs*/

/*
#include <stdio.h>      //printf
#include <stdlib.h>     // system, NULL, EXIT_FAILURE
/*
int main ()
{
  int i;
  printf ("Checking if processor is available...");
  if (system(NULL)) puts ("Ok");
    else exit (EXIT_FAILURE);
  printf ("Executing command DIR...\n");
  i=system ("ls");
  printf ("The value returned was: %d.\n",i);
  return 0;
}*/
