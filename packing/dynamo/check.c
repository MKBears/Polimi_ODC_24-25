int check(long param_1,long *param_2)

{
  long lVar1;
  long lVar2;
  char *in_RAX;
  long lVar3;
  long *plVar4;
  
  *in_RAX = 1;
  *in_RAX = *in_RAX + (char)in_RAX;
  plVar4 = (long *)(param_1 + 8);
  lVar3 = 9;
  while( true ) {
    if (lVar3 == 0) {
      return 1;
    }
    lVar1 = *plVar4;
    lVar2 = *param_2;
    plVar4 = plVar4 + 1;
    param_2 = param_2 + 1;
    if (lVar1 != lVar2) break;
    lVar3 = lVar3 + -1;
  }
  return 0;
}