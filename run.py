#coding: utf-8

from ich.eapauth import EAPAuth

from config import infos


e = EAPAuth(infos)


if __name__ == '__main__':
    e.run()
