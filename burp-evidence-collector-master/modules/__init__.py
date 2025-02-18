"""
The __init__.py files are required to make Python treat the directories as containing packages; this is done to
prevent directories with a common name, such as string, from unintentionally hiding valid modules that occur later on
the module search path. In the simplest case, __init__.py can just be an empty file, but it can also execute
initialization code for the package

https://docs.python.org/2.7/tutorial/modules.html#packages
"""
