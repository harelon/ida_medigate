from setuptools import setup, find_packages

setup(name='ida_medigate',
      version='1.0.1',
      description='IDA plugin for parsing RTTI and creating object vtable structs',
      url='https://github.com/medigateio/ida_medigate',
      packages=find_packages(where="src"),
      package_dir={"": "src"},
      python_requires=">=3",
      zip_safe=True
      )
