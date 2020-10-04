#include <stdio.h>
long sum=0;
int v;
int n=0;
int main()
{
    while(1){
        char name[30];
        printf("请输入要计算的文件\n");
        scanf("%s",name);
        FILE *fp;
        fp=fopen(name,"r");
        while(1)
        {
            if(fscanf(fp,"%d",&v)==1)
            { 
                sum=sum+v;
                n++;
            }
            if(feof(fp))break;
        }
        fclose(fp);
        printf("%ld毫秒\n",sum/n);
    }
    return 0;
}
