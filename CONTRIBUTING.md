# Contributing to sqlmap

## Reporting bugs

**Bug reports are welcome**!
Please report all bugs on the [issue tracker](https://github.com/sqlmapproject/sqlmap/issues).

### Guidelines

* Before you submit a bug report, search both [open](https://github.com/sqlmapproject/sqlmap/issues?q=is%3Aopen+is%3Aissue) and [closed](https://github.com/sqlmapproject/sqlmap/issues?q=is%3Aissue+is%3Aclosed) issues to make sure the issue has not come up before. Also, check the [user's manual](https://github.com/sqlmapproject/sqlmap/wiki) for anything relevant.
* Make sure you can reproduce the bug with the latest development version of sqlmap.
* Your report should give detailed instructions on how to reproduce the problem. If sqlmap raises an unhandled exception, the entire traceback is needed. Details of the unexpected behaviour are welcome too. A small test case (just a few lines) is ideal.
* If you are making an enhancement request, lay out the rationale for the feature you are requesting. *Why would this feature be useful?*
* If you are not sure whether something is a bug, or want to discuss a potential new feature before putting in an enhancement request, the [mailing list](https://lists.sourceforge.net/lists/listinfo/sqlmap-users) is a good place to bring it up.

## Submitting code changes

All code contributions are greatly appreciated. First off, clone the [Git repository](https://github.com/sqlmapproject/sqlmap), read the [user's manual](https://github.com/sqlmapproject/sqlmap/wiki) carefully, go through the code yourself and [drop us an email](mailto:dev@sqlmap.org) if you are having a hard time grasping its structure and meaning. We apologize for not commenting the code enough - you could take a chance to read it through and [improve it](https://github.com/sqlmapproject/sqlmap/issues/37).

Our preferred method of patch submission is via a Git [pull request](https://help.github.com/articles/using-pull-requests).
Many [people](https://raw.github.com/sqlmapproject/sqlmap/master/doc/THANKS.md) have contributed in different ways to the sqlmap development. **You** can be the next!

### Guidelines

In order to maintain consistency and readability throughout the code, we ask that you adhere to the following instructions:

* Each patch should make one logical change.
* Wrap code to 76 columns when possible.
* Avoid tabbing, use four blank spaces instead.
* Before you put time into a non-trivial patch, it is worth discussing it on the [mailing list](https://lists.sourceforge.net/lists/listinfo/sqlmap-users) or privately by [email](mailto:dev@sqlmap.org).
* Do not change style on numerous files in one single pull request, we can [discuss](mailto:dev@sqlmap.org) about those before doing any major restyling, but be sure that personal preferences not having a strong support in [PEP 8](http://www.python.org/dev/peps/pep-0008/) will likely to be rejected.
* Make changes on less than five files per single pull request - there is rarely a good reason to have more than five files changed on one pull request, as this dramatically increases the review time required to land (commit) any of those pull requests.
* Style that is too different from main branch will be ''adapted'' by the developers side.
* Do not touch anything inside `thirdparty/` and `extra/` folders.

### Licensing

By submitting code contributions to the sqlmap developers, to the mailing list, or via Git pull request, checking them into the sqlmap source code repository, it is understood (unless you specify otherwise) that you are offering the sqlmap copyright holders the unlimited, non-exclusive right to reuse, modify, and relicense the code. This is important because the inability to relicense code has caused devastating problems for other software projects (such as KDE and NASM). If you wish to specify special license conditions of your contributions, just say so when you send them.
