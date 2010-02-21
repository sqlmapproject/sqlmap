Compile only the Release version because the Runtime library option
(Project Properties -> Configuration Properties -> C/C++ -> Code
Generation) is set to "Multi-threaded (/MT)", which statically links
everything into executable and doesn't compile Debug version at all.
