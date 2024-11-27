import Paeks17_mod

Paeks17_mod.setup(1)
Paeks17_mod.setup(2)
Ca, Cb = Paeks17_mod.encrypt(1,'Hello')
Tw = Paeks17_mod.trapdoor(1,'Hello')
Tw2 = Paeks17_mod.trapdoor(2,'Bello')
re = Paeks17_mod.test(1,Tw,Ca,Cb)
print(re)
re = Paeks17_mod.test(2,Tw2,Ca,Cb)
print(re)

pk,sk = Paeks17_mod.exportkey(1)
Paeks17_mod.importkey(2,pk,sk)
Tw2 = Paeks17_mod.trapdoor(2,'Hello')
re = Paeks17_mod.test(2,Tw2,Ca,Cb)
print(re)
