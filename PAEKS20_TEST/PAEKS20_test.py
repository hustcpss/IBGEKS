import Paeks20_mod

Paeks20_mod.setup(1)
Paeks20_mod.setup(2)
Ca, Cb = Paeks20_mod.encrypt(1,'Hello')
Tw = Paeks20_mod.trapdoor(1,'Hello')
Tw2 = Paeks20_mod.trapdoor(2,'Bello')
re = Paeks20_mod.test(1,Tw,Ca,Cb)
print(re)
re = Paeks20_mod.test(2,Tw2,Ca,Cb)
print(re)

Tw2 = Paeks20_mod.trapdoor(2,'Hello')
re = Paeks20_mod.test(2,Tw2,Ca,Cb)
print(re)

Ca, Cb = Paeks20_mod.encrypt(2,'Hello')
re = Paeks20_mod.test(2,Tw2,Ca,Cb)
print(re)
