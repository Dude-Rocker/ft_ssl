/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_std.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/25 22:05:51 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/22 16:19:42 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

void	free_all(char **av, char *ln, t_ssl *ssl)
{
	int		i;

	i = 0;
	if (ssl)
	{
		ssl->res = 0;
		ssl->stream = 0;
		ssl->type[1] = 6;
		ssl->type[0] = (ssl->type[0] == DES ? DES_CBC: ssl->type[0]);
		while (++i < 5)
			ssl->prog[i] = 0;
		if (ssl->type[0] < SHA_384)
			ssl->type[1] = (ssl->type[0] == MD_5 ? 0 : 1);
		else if (ssl->type[0] < DES)
			ssl->type[1] = (ssl->type[0] == BASE_64 ? 3 : 2);
		else if (ssl->type[0] < RAND)
			ssl->type[1] = (ssl->type[0] == DES_ECB ? 5 : 4);
		return ;
	}
	while (av[i])
		free(av[i++]);
	free(av);
	free(ln);
}

static int	ft_rand(t_ssl *ssl, char **av, int i, size_t c)
{
	while (av[++i])
	{
		if (!ssl->flg[OF] && !ssl->stream)
			ssl->stream = av[i];
		else if (!ssl->flg[HF] && !ft_strcmp(av[i], "-h"))
			ssl->flg[HF] = 1;
		else if (ssl->flg[OF] == 1 && !ft_strcmp(av[i], "-o"))
			ssl->flg[OF] = 0;
		else if (!ssl->flg[DF] && ft_isdigit(av[i][0]) && (ssl->flg[DF] = 1))
			ssl->size = ft_basetoint(av[i], 10);
		else
			break ;
	}
	if (!ssl->flg[DF] || av[i] || (!ssl->flg[OF] && !ssl->stream))
		return (1);
	if (!ssl->flg[OF])
		ssl->flg[OF] = open(ssl->stream, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ssl->stream = ft_strnew(0);
	while (ssl->flg[HF] && c++ < ssl->size)
	{
		if (ft_strlen((ssl->stream = ft_itoabase(rand() % 256, 16, 97))) < 2)
			ssl->stream = ft_joinfree("0", ssl->stream, 2);
		ssl->stream = ft_joinfree(ssl->stream, ssl->stream, 3);
	}
	return (0);
}

static void	ft_vers(t_ssl *ssl, char *av, int j)
{
	if (av)
	{
		write(2, "usage:version -[avbd]\n", 22);
		return ;
	}
	if (ssl->flg[AF] || ssl->flg[VF] || !(ssl->flg[BF] + ssl->flg[DF]))
		ft_printf("ft_ssl 1.0v  21 Aug 2018\n");
	if (ssl->flg[AF] || ssl->flg[BF])
		ft_printf("built on: 27 Aug 2018\n");
	if (ssl->flg[AF] || ssl->flg[DF])
	{
		while (ssl->prog[0][j] != 'f')
			j--;
		ft_printf("FT_SSLDIR: \"%.*s\"\n", j, ssl->prog[0]);
	}
}

void		ft_command(t_ssl *ssl, char **av, int i)
{
	if (ssl->type[0] == RAND)
	{
		ssl->size = 0;
		if (ft_rand(ssl, av, i - 1, 0))
		{
			write(2, "Usage: rand [options] num\nwhere options are\n-o file\
\t\t- write to file\n-h\t\t- hex encode output\n", 93);
			return ;
		}
		if (!ssl->flg[HF])
		{
			free(ssl->stream);
			ssl->stream = ft_strnew(ssl->size + 1);
			i = -1;
			while ((size_t)++i < ssl->size)
				ssl->stream[i] = rand();
		}
		ft_dprintf(ssl->flg[OF], "%s\n", ssl->stream);
		free(ssl->stream);
	}
	else
		ft_vers(ssl, av[i], ft_strlen(ssl->prog[0]));
}
