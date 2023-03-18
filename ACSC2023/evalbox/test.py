print(os:=__import__('os'),d:=os.scandir(os.open(".",0)),list(filter(lambda x: x.name, d)))
