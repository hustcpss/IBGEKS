import SAPeks_mod

SAPeks_mod.setup(1)
SAPeks_mod.setup(2)
Ca, Cb = SAPeks_mod.encrypt(1,'Hello')
Tw = SAPeks_mod.trapdoor(1,'Hello')
Tw2 = SAPeks_mod.trapdoor(2,'Bello')
re = SAPeks_mod.test(1,Tw,Ca,Cb)
print(re)
re = SAPeks_mod.test(2,Tw2,Ca,Cb)
print(re)

pk,sk = SAPeks_mod.exportkey(1)
SAPeks_mod.importkey(2,pk,sk)
Tw2 = SAPeks_mod.trapdoor(2,'Hello')
re = SAPeks_mod.test(2,Tw2,Ca,Cb)
print(re)