/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_convertunicode.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gemaroul <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/30 00:12:32 by gemaroul          #+#    #+#             */
/*   Updated: 2018/10/30 00:12:38 by gemaroul         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../../include/libft.h"

char	*ft_convertunicode(wchar_t c)
{
	char	*str;

	str = ft_strnew(4);
	if (c <= 0x7F)
		str[0] = c;
	else if (c <= 0x7FF)
	{
		str[0] = (c >> 6) + 0xC0;
		str[1] = (c & 0x3F) + 0x80;
	}
	else if (c < 0xFFFF)
	{
		str[0] = (c >> 12) + 0xE0;
		str[1] = ((c >> 6) & 0x3F) + 0x80;
		str[2] = (c & 0x3F) + 0x80;
	}
	else
	{
		str[0] = ((c >> 18) + 0xF0);
		str[1] = ((c >> 12) & 0x3F) + 0x80;
		str[2] = ((c >> 6) & 0x3F) + 0x80;
		str[3] = (c & 0x3F) + 0x80;
	}
	return (str);
}
