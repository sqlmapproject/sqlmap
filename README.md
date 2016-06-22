# sqlmap

Because sqlmap only support GoogleDork. I fork original project and add BaiduDork support.

You can use --use-baidu in cmd line to specify using baidu engine to replace google engine. Other arguments are same with GoogleDork.

ex.
python sqlmap.py -g "测试 inurl:jsp?id=" --use-baidu --gpage=8 --smart --beep --batch