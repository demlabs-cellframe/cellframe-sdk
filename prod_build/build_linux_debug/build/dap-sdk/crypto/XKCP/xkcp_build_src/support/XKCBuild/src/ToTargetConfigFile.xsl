<?xml version='1.0' encoding="UTF-8"?>
<!--
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Implementation by Gilles Van Assche, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
-->
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    version='1.0'>

<xsl:output method="text" indent="no" encoding="UTF-8"/>

<xsl:template match="text()"/>

<xsl:template match="config">
    <xsl:text>#define </xsl:text>
    <xsl:value-of select="."/>
    <xsl:text>
</xsl:text>
</xsl:template>

<xsl:template match="target">
    <xsl:text>/* File generated by ToTargetConfigFile.xsl */

</xsl:text>
    <xsl:apply-templates match="config"/>
</xsl:template>

</xsl:stylesheet>
