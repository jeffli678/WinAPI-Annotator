import os
import json
from binaryninja import PluginCommand
import winapi

PluginCommand.register_for_function(
  "WinAPI Annotator",
  "Annotate Windows API functions with arguments",
  winapi.run_plugin)
