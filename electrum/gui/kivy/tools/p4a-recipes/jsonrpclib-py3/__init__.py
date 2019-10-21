from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.toolchain import current_directory
import os

class JsonRpcLibPy3(PythonRecipe):
    version = '0'
    url = 'https://github.com/ly0/jsonrpclib-py3/archive/master.zip'
    depends = []
    conflicts = ['jsonrpclib']

    def prebuild_arch(self, arch):
        super().prebuild_arch(arch)
        with current_directory(self.get_build_dir(arch.arch)):
            with open('jsonrpclib/SimpleJSONRPCServer.py', 'r+') as f:
                content = f.read()
                content = content.replace("except Exception, e:", "except Exception as e:")
                n = content.find("print ", 0)
                while n != -1:
                    new_content = []
                    new_content.append(content[:n+5])
                    new_content.append("(")
                    nl = content.find("\n", n + 5)
                    new_content.append(content[n+6:nl])
                    new_content.append(")")
                    new_content.append(content[nl:])
                    content = "".join(new_content)
                    n = content.find("print ", nl)
                f.seek(0)
                f.truncate()
                f.write(content)

    def postbuild_arch(self, arch):
        super().postbuild_arch(arch)
        with current_directory(self.get_build_dir(arch.arch)):
            print(os.listdir())

recipe = JsonRpcLibPy3()




