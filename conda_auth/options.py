"""
Module for custom click.Option classes
"""
from __future__ import annotations
import click
from typing import Any
from collections.abc import Mapping


class ConditionalOption(click.Option):
    """
    Custom option that does the following things:

    - Define ``mutually_exclusive`` options that cannot be passed together
    - Control prompting in the presence of other options via ``prompt_when``
    """
    def __init__(self, *args, **kwargs):
        self.not_required_if = set(kwargs.pop("not_required_if", []))

        self.prompt_when = set(kwargs.pop("prompt_when", []))
        if self.prompt_when:
            # ensure prompt text is configured,
            # conditionally control whether we prompt in handle_parse_result
            kwargs["prompt"] = True

        self.mutually_exclusive = set(kwargs.pop("mutually_exclusive", []))
        if self.mutually_exclusive:
            # augment help blurb to include details about mutually exclusive options
            help_ = kwargs.get("help", "")
            mutex = ", ".join(map(repr, self.mutually_exclusive))
            kwargs["help"] = f"{help_}; cannot be used with these options: {mutex}"

        super().__init__(*args, **kwargs)

    def handle_parse_result(
        self,
        ctx: click.Context,
        opts: Mapping[str, Any],
        args: list[str],
    ) -> tuple[Any, list[str]]:
        # determine whether mutex has been violated
        if self.mutually_exclusive.intersection(opts) and self.name in opts:
            mutex = ", ".join(map(repr, self.mutually_exclusive))
            raise click.UsageError(f"Option {self.name!r} cannot be used with {mutex}")

        # determine whether we want to prompt for this argument
        if self.prompt_when and not self.prompt_when.intersection(opts):
            self.prompt = None

        if (
            self.not_required_if
            and self.name not in opts
            and not self.not_required_if.intersection(opts)
        ):
            required = {self.name, *self.not_required_if}
            raise click.MissingParameter(
                ctx=ctx,
                param_type="option",
                param_hint=" / ".join(sorted(map(repr, required))),
            )

        return super().handle_parse_result(ctx, opts, args)
