#include "Out.h"
#include <stdio.h>

void Out$String(MIC$AP str)
{
    const char* tmp = (const char*)str.$;
    printf("%s", tmp);
}

void Out$Ln()
{
    printf("\n");
}

void Out$Int(int i, short n)
{
    printf("%d", i);
}
