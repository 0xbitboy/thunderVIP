# -*- coding: utf-8 -*-
import login
def main():

    with open("account.txt") as  f:
        for account in f:
            uAndp = account.split(" ");
            print(account,login.login(uAndp[0],uAndp[1])[1])


if __name__=="__main__":
    main()