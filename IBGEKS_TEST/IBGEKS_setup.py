from distutils.core import setup, Extension
# Specify the module name and source files
source_files = ["IBGEKS.cpp", "IBGEKS_Encap.cpp"]
MOD = 'Ibgeks_mod'
setup(  name = MOD,
        version = '0.1',
        description= 'our',
        author = 'ldlkancolle',
        author_email = 'ldlkancolle@outlook.com',
        ext_modules = [Extension( MOD,
                sources = source_files,
                extra_link_args = ['-lpbc','-lgmp','-lcrypto'],
                extra_compile_args = ['--std=c11','-w']
                )
                ]
    )
