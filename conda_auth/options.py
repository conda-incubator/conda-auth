"""
Module for custom click.Option classes
"""
import click


class CustomOption(click.Option):
    """
    Custom option that does the following things:

    - Allows you to define a "mutually_exclusive" tuple so certain options cannot be passed
      together
    - If ``prompt=True`` is set, can optionally control it to be prompted only in the presence of
      other options via ``prompt_when``
    - Adds options which have been passed to ``ctx.obj.used_options``
    """
    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop("mutually_exclusive", []))
        self.prompt_when = kwargs.pop("prompt_when", None)
        help_message = kwargs.get("help", "")

        if self.mutually_exclusive:
            ex_str = ", ".join(f'"{option}"' for option in self.mutually_exclusive)
            kwargs[
                "help"
            ] = f"{help_message}; cannot be used with these options: {ex_str}"

        super().__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        if self.name in opts:
            ctx.obj.used_options.add(self.name)

        if self.prompt_when is not None and self.prompt_when not in opts:
            return None, args

        if self.mutually_exclusive.intersection(opts) and self.name in opts:
            mutually_exclusive = ", ".join(
                f'"{option}"' for option in self.mutually_exclusive
            )
            raise click.UsageError(
                f'Option "{self.name}" cannot be used with {mutually_exclusive}'
            )

        return super().handle_parse_result(ctx, opts, args)
