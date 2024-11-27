import Peks_mod

Peks_mod.setup(1)
Peks_mod.setup(2)
Ca, Cb = Peks_mod.encrypt(1,'Hello')
Tw = Peks_mod.trapdoor(1,'Hello')
Tw2 = Peks_mod.trapdoor(2,'Bello')
re = Peks_mod.test(1,Tw,Ca,Cb)
print(re)
re = Peks_mod.test(2,Tw2,Ca,Cb)
print(re)

pk,sk = Peks_mod.exportkey(1)
Peks_mod.importkey(2,pk,sk)
Tw2 = Peks_mod.trapdoor(2,'Hello')
re = Peks_mod.test(2,Tw2,Ca,Cb)
print(re)
