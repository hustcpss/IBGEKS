import Ibgeks_mod

Ibgeks_mod.setup(1)
Ibgeks_mod.setup(2)


ID1 = 'Alice'
ID2 = 'Bob'

gsk1 = Ibgeks_mod.join(1, ID1)
Ca, Cb = Ibgeks_mod.encrypt(1,'Hello', ID1, gsk1)
Tw = Ibgeks_mod.trapdoor(1,'Hello')


gsk2 = Ibgeks_mod.join(1, ID2)
Ca2, Cb2 = Ibgeks_mod.encrypt(1,'Hello', ID2, gsk2)

print(Ibgeks_mod.test(1,Tw,Ca,Cb))
print(Ibgeks_mod.test(1,Tw,Ca2,Cb2))

sk = Ibgeks_mod.exportkey(1)
Ibgeks_mod.importkey(2,sk)

Tw2 = Ibgeks_mod.trapdoor(2,'Hello')
print(Ibgeks_mod.test(2,Tw2,Ca,Cb))
