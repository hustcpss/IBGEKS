from distutils.core import setup, Extension
# Specify the module name and source files
source_files = ["PAEKS17.cpp", "PAEKS17_encap.cpp"]
MOD = 'Paeks17_mod'
setup(  name = MOD,
        version = '0.1',
        description= 'DB04',
        author = 'ldlkancolle',
        author_email = 'ldlkancolle@outlook.com',
        ext_modules = [Extension( MOD,
                sources = source_files,
                extra_link_args = ['-lpbc','-lgmp','-lcrypto'],
                extra_compile_args = ['--std=c11','-w']
                )
                ]
    )
