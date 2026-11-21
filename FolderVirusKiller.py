# -*- coding: utf-8 -*-
"""
程序入口（兼容旧文件名）
------------------------
源码运行：python FolderVirusKiller.py
命令行回滚：python FolderVirusKiller.py --restore "<隔离目录>"
业务逻辑已迁移到 modules/ 下的各个模块。
"""
import sys


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--restore":
        from modules.folder_virus import Engine
        Engine.restore(sys.argv[2], print)
        return
    from core.app import main as app_main
    app_main()


if __name__ == "__main__":
    main()
