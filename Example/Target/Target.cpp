#include <cstdio>

extern "C" {

void another_secret_method();

void super_secret_method()
{
	puts("You will never find me!");
	another_secret_method();
}

void another_secret_method()
{
	puts("I really really really really really love Linux!");
}

}
