"""blankflash-forge: build a device's blankflash from a same-SoC sibling's signed loader.

The signed Firehose ``programmer.elf`` in a Qualcomm/Motorola blankflash is
authenticated per SoC + OEM key, not per device -- so a sibling in the same SoC
family donates the one piece you cannot extract from your own device, while your
own stock firmware supplies everything else.
"""

from . import donor, forge, singleimage, target

__all__ = ["singleimage", "donor", "target", "forge"]
__version__ = "0.1.0"
