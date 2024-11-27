from distutils.core import setup, Extension

MOD = 'Popa_mod'
setup(  name = MOD,
        version = '0.1',
        description= 'Liu23TIFS_IBGEKS',
        author = 'ldlkancolle',
        author_email = 'ldlkancolle@outlook.com',
        ext_modules = [Extension( MOD,
                                sources = ['IBGEKS.c'],
                                extra_link_args = ['-lpbc','-lgmp','-lcrypto'],
                                extra_compile_args = ['--std=c99','-w']
                                )
                                ]
    )
