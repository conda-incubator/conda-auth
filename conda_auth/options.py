"""
Module for custom click.Option classes
"""
import click


class MutuallyExclusiveOption(click.Option):
    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop("mutually_exclusive", []))
        help_message = kwargs.get("help", "")

        if self.mutually_exclusive:
            ex_str = ", ".join(f'"{option}"' for option in self.mutually_exclusive)
            kwargs[
                "help"
            ] = f"{help_message}; cannot be used with these options: {ex_str}"

        super().__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        if self.mutually_exclusive.intersection(opts) and self.name in opts:
            mutually_exclusive = ", ".join(
                f'"{option}"' for option in self.mutually_exclusive
            )
            raise click.UsageError(
                f'Option "{self.name}" cannot be used with {mutually_exclusive}'
            )

        return super().handle_parse_result(ctx, opts, args)
