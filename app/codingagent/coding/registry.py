"""The complete tool set exposed to the model."""

from strands.vended_tools import make_handoff_to_user

from .fs_tools import (
    apply_patch,
    delete_path,
    edit_file,
    list_directory,
    make_directory,
    move_path,
    read_file,
    undo_change,
    write_file,
)
from .git_tools import git_branch, git_commit, git_diff, git_init, git_log, git_push, git_status
from .plan_tools import todo
from .search_tools import glob_files, grep_search, project_overview
from .shell_tools import background_process, run_command, run_tests
from .web_tools import web_fetch

ask_user = make_handoff_to_user(
    name="ask_user",
    description=(
        "Ask the user a clarifying question or request a decision, then wait for the answer. "
        "Use sparingly, with one short, specific question."
    ),
)


def get_tools() -> list:
    return [
        # explore
        project_overview, list_directory, glob_files, grep_search, read_file,
        # change
        edit_file, write_file, apply_patch, move_path, delete_path, make_directory, undo_change,
        # run & verify
        run_command, run_tests, background_process,
        # version control
        git_status, git_diff, git_log, git_branch, git_init, git_commit, git_push,
        # research & coordination
        web_fetch, todo, ask_user,
    ]
