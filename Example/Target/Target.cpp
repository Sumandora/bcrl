#include <cstdio>

extern "C" {

void anotherSecretMethod();

void superSecretMethod()
{
	puts("You will never find me!");
	anotherSecretMethod();
}

void anotherSecretMethod()
{
	puts("I really really really really really love Linux!");
}

}
