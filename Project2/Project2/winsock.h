/*	winsock.h 
	CPS 472 Sample Code

	Define a class that handles socket APIs
*/


//#pragma once 
#include <stdio.h>
#include <winsock2.h>
#include <time.h>

class Winsock {

public:
	SOCKET	OpenSocket (void); 

};